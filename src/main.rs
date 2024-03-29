use sha2::{Digest, Sha256};
use std::collections::{HashSet, HashMap};
use std::ffi::c_void;
use std::ffi::CString;
use std::io::prelude::*;
use std::io::{self, Read, Write};
use std::os::windows::ffi::EncodeWide;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering, AtomicIsize, AtomicI32, AtomicU32};
use std::ptr;
use std::time::Duration;
use windows::{
    core::*, Data::Xml::Dom::*, Win32::Foundation::*, Win32::Security::*,
    Win32::Storage::FileSystem::*, Win32::System::Diagnostics::Debug::*,
    Win32::System::Diagnostics::ToolHelp::*, Win32::System::Kernel::*,
    Win32::System::LibraryLoader::*, Win32::System::Memory::*, Win32::System::SystemServices::*,
    Win32::System::Threading::*, Win32::UI::WindowsAndMessaging::*,
    Win32::System::ProcessStatus::*,
};
use std::fmt;
use rand::prelude::*;
use std::thread;
use std::net::TcpListener;
use std::sync::Arc; // Import Arc for thread-safe reference counting

const CONTEXT_FULL: u32 = 0x00010007;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;

// TODO generic GetLastError handler

struct Debugee {
    h_process: HANDLE,
    process_handle: HANDLE,
    pid: u32,
    debugger_active: bool,
    h_thread: HANDLE,
    context: CONTEXT, // ?
    exception_code: NTSTATUS,
    exception_address: *mut c_void,
    thread_list: Vec<u32>,
    thread_handles: HashMap<u32, HANDLE>,
}

pub struct CrashStatus {
    crash_status: AtomicI32,
    total_crashes: AtomicU32,
}

pub trait Debugger {
    fn run(&mut self, cs: &Arc<CrashStatus>);
    fn load(&mut self, path_to_binary: String);
    fn create_process(&mut self) -> u32;
    fn open_process(&mut self, pid: u32) -> HANDLE;
    fn attach_process(&mut self, pid: u32);
    fn debug_handler(&mut self, cs: &Arc<CrashStatus>);
    fn open_thread(&mut self, thread_id: u32) -> HANDLE;
    fn get_thread_context(&mut self, thread_id: u32);
    fn function_resolve(&mut self, dll: PCSTR, function: PCSTR);
    fn enumerate_threads(&mut self);
    fn debug_set_process_kill_on_exit(&mut self);
    fn terminate_process(&mut self, h_process: HANDLE);
    fn get_process_id(&mut self, h_process: HANDLE) -> u32;
    fn get_hash(&mut self, input: usize) -> String;
    fn detach(&mut self);
}

pub trait X {
    fn get_cs(&mut self) -> i32;
    fn set_cs(&mut self, x: i32);
}

impl X for CrashStatus {
    fn get_cs(&mut self) -> i32 {
        self.crash_status.load(Ordering::SeqCst)
    }

    fn set_cs(&mut self, x: i32) {
        self.crash_status.store(x, Ordering::SeqCst);
    }
}

impl Default for CrashStatus {
    fn default() -> CrashStatus {
        CrashStatus {
            crash_status: 0.into(),
            total_crashes: 0.into(),
        }
    }
}


impl Default for Debugee {
    fn default() -> Debugee {
        Debugee {
            h_process: Default::default(),
            pid: 0,
            process_handle: Default::default(),
            debugger_active: false,
            h_thread: Default::default(),
            context: CONTEXT {
                ContextFlags: CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS,
                ..Default::default()
            },
            exception_code: NTSTATUS::default(),
            exception_address: std::ptr::null_mut(),
            thread_list: Vec::new(),
            thread_handles: HashMap::new(),
        }
    }
}


impl Debugger for Debugee {
    fn run(&mut self, cs: &Arc<CrashStatus>) {
        while self.debugger_active == true {
            self.debug_handler(cs);
        }
    }

    fn load(&mut self, path_to_binary: String) {
        let path_to_binary = CString::new(path_to_binary).unwrap();
        let path_to_binary = path_to_binary.as_bytes_with_nul().as_ptr();
        dbg!(path_to_binary);
        let creation_flags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;
        let mut startupinfo = STARTUPINFOA {
            dwFlags: STARTUPINFOW_FLAGS(0x1),
            wShowWindow: 0x0,
            ..Default::default()
        };
        dbg!(startupinfo);
        let mut process_information = PROCESS_INFORMATION {
            ..Default::default()
        };
        unsafe {
            let process = CreateProcessA(
                PCSTR(path_to_binary),
                PSTR(ptr::null_mut()),
                ptr::null(),
                ptr::null(),
                BOOL(0),
                creation_flags,
                0 as *mut c_void,
                PCSTR(ptr::null_mut()),
                &mut startupinfo,
                &mut process_information,
            );

            if process.as_bool() == true {
                print!("[*] Process is successfully launched!\n");
                print!("[*] Process ID: {}\n", process_information.dwProcessId);
                self.pid = process_information.dwProcessId;
                // attach internal
                // self.attach_process(self.pid);
                //dbg!(self);

                //sleep(Duration::from_secs(10));
                //WaitForSingleObject(process_information.hProcess, 0xFFFFFFFF);
            }
        }
    }
    fn create_process(&mut self) -> u32 {
        todo!()
    }
    fn open_process(&mut self, pid: u32) -> HANDLE {
        unsafe {
            let handle: HANDLE =
                OpenProcess(PROCESS_ALL_ACCESS, false, pid).expect("Failed to open the process");
            println!("[+] OpenProcess is successful!");
            handle
        }
    }
    fn attach_process(&mut self, pid: u32) {
        unsafe {
            // TODO check bitness of debugee and debugger
            println!("[*] Attaching process: {}", pid);
            self.h_process = self.open_process(pid);

            self.debug_set_process_kill_on_exit();

            println!("[*] Trying to Debug Active Process");
            if DebugActiveProcess(pid).as_bool() == true {
                self.debugger_active = true;
                self.pid = pid;
                println!("[+] Debugging active process!");
            } else {
                println!("[-] Unable to attach to the process.");
                let win32_error = GetLastError();
                println!(
                    "WIN32_ERROR: {:?}, Error message: {:?}",
                    win32_error,
                    win32_error.to_hresult().message()
                );
            }
        }
    }
    fn debug_handler(&mut self, cs: &Arc<CrashStatus>) {
        unsafe {
            let mut debug_event = DEBUG_EVENT::default();

            let continue_status = DBG_CONTINUE;


            if WaitForDebugEvent(&mut debug_event, 100).as_bool() == true {
                //let create_process = CREATE_PROCESS_DEBUG_INFO::default();

                //self.h_thread = self.open_thread(debug_event.dwThreadId);
                //println!("Event Code: {:?}, Thread ID: {}", debug_event.dwDebugEventCode, debug_event.dwThreadId);

                let tid = debug_event.dwThreadId;
                let pid = debug_event.dwProcessId;    

                if debug_event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT {
                    println!("CREATE_PROCESS_DEBUG_EVENT");
                    let create_process = debug_event.u.CreateProcessInfo;

                    self.process_handle = create_process.hProcess;
                } else if debug_event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT {
                    println!("CREATE_THREAD_DEBUG_EVENT");
                    let create_thread = debug_event.u.CreateThread;
                    self.thread_handles.insert(tid, create_thread.hThread);
                } else if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                    let exception_record = debug_event.u.Exception.ExceptionRecord;
                    self.exception_code = exception_record.ExceptionCode;
                    self.exception_address = exception_record.ExceptionAddress;

                    if self.exception_code == EXCEPTION_ACCESS_VIOLATION {
                        println!("Access Violation Detected.");
                        println!(
                            "Exception: {:?}, Exception Address: {:?}, Thread ID: {}",
                            self.exception_code, self.exception_address, tid
                        );

                        // set crash status
                        cs.as_ref().crash_status.fetch_add(1, Ordering::SeqCst);
                        cs.as_ref().total_crashes.fetch_add(1, Ordering::SeqCst);
                        let crash_no = cs.as_ref().total_crashes.load(Ordering::SeqCst);
                        
                        self.get_thread_context(tid);
                        let mut err_type = String::new();
                        if exception_record.ExceptionInformation[0] == 0 {
                            err_type = "read".to_string();
                        } else if exception_record.ExceptionInformation[0] == 1 {
                            err_type = "write".to_string();
                        } else if exception_record.ExceptionInformation[0] == 8 {
                            err_type = "dep".to_string();
                        }
                        // let mut rng = rand::thread_rng();
                        // let r_num: u32 = rng.gen();
                        // let random_hash = self.get_hash(r_num.try_into().unwrap());
                    
                        let filename_raw = format!(
                            "crash_{}_{:08x}_{}_{:08x}.dmp",
                            crash_no, self.exception_code.0, err_type, self.exception_address as usize
                        );

                        let filename_c = filename_raw.clone();
                        let filename = CString::new(filename_raw).unwrap();
                        let filename = filename.as_bytes_with_nul().as_ptr();
                        println!("Creating file");
                        if !Path::new(&filename_c).is_file() {
                            let fd = CreateFileA(
                                PCSTR(filename),
                                FILE_ACCESS_FLAGS(GENERIC_READ | GENERIC_WRITE),
                                FILE_SHARE_NONE,
                                ptr::null_mut(),
                                CREATE_NEW,
                                FILE_FLAGS_AND_ATTRIBUTES::default(),
                                HANDLE::default(),
                            );
                            let fd = fd.unwrap();
                            println!("File Created");

                            let exception_record = &mut debug_event.u.Exception.ExceptionRecord;
                            let mut ep = EXCEPTION_POINTERS {
                                ExceptionRecord: exception_record,
                                ContextRecord: &mut self.context,
                            };

                            let mei = MINIDUMP_EXCEPTION_INFORMATION {
                                ThreadId: tid,
                                ExceptionPointers: &mut ep,
                                ClientPointers: BOOL(0),
                            };
                            println!("Getting MiniDump");

                            let dump_status = MiniDumpWriteDump(
                                self.process_handle,
                                pid,
                                fd,
                                MiniDumpWithFullMemory | MiniDumpWithHandleData,
                                &mei,
                                ptr::null_mut(),
                                ptr::null_mut(),
                            );
                            if dump_status.as_bool() != true {
                                println!("MiniDumpWriteDump error");
                                let win32_error = GetLastError();
                                println!(
                                    "WIN32_ERROR: {:?}, Error message: {:?}",
                                    win32_error,
                                    win32_error.to_hresult().message()
                                );
                            }
                            println!("[+] MiniDump");
                            
                        }
                        self.detach();
                        self.terminate_process(self.h_process);
                    } else if self.exception_code == EXCEPTION_BREAKPOINT {
                        println!("EXCEPTION_BREAKPOINT");
                    } else if self.exception_code == EXCEPTION_GUARD_PAGE {
                        println!("EXCEPTION_GUARD_PAGE");
                    } else if self.exception_code == EXCEPTION_SINGLE_STEP {
                        println!("EXCEPTION_SINGLE_STEP");
                    }
                } else if debug_event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT {
                    println!("LOAD_DLL_DEBUG_EVENT");
                } else if debug_event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT {
                    println!("EXIT_THREAD_DEBUG_EVENT");
                    assert!(
                        self.thread_handles.remove(&tid).is_some(),
                        "Got exit threat event for nonexistant thread"
                    );
                } else if debug_event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT {
                    println!("EXIT_PROCESS_DEBUG_EVENT");
                } else if debug_event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT {
                    println!("UNLOAD_DLL_DEBUG_EVENT");
                }
                ContinueDebugEvent(
                    debug_event.dwProcessId,
                    debug_event.dwThreadId,
                    continue_status.0.try_into().unwrap(),
                );
            }
        }
    }
    fn open_thread(&mut self, thread_id: u32) -> HANDLE {
        unsafe {
            let handle: HANDLE = OpenThread(THREAD_ALL_ACCESS, None, thread_id).unwrap();
            if handle.is_invalid() == true {
                println!("[*] Could not obtain a valid thread handle");
                HANDLE(-1)
            } else {
                self.h_thread
            }
        }
    }
    fn get_thread_context(&mut self, thread_id: u32) {
        unsafe {
            if GetThreadContext(self.thread_handles[&thread_id], &mut self.context).as_bool()
                == true
            {
                println!("[+] Got thread context");
            } else {
                let win32_error = GetLastError();
                println!(
                    "WIN32_ERROR: {:?}, Error message: {:?}",
                    win32_error,
                    win32_error.to_hresult().message()
                );
                println!("[*] Failed to get thread context!");
            }
        }
    }
    fn function_resolve(&mut self, dll: PCSTR, function: PCSTR) {
        unsafe {
            let handle = GetModuleHandleA(dll).unwrap();
            let address = GetProcAddress(handle, function);
            let address = address.unwrap();
            println!("printf: {}", address as usize);
        }
    }
    fn enumerate_threads(&mut self) {
        let mut thread_entry = THREADENTRY32::default();

        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.pid).unwrap();
            thread_entry.dwSize = std::mem::size_of::<THREADENTRY32>().try_into().unwrap();
            let success = Thread32First(snapshot, &mut thread_entry);
            while success.as_bool() == true {
                if thread_entry.th32OwnerProcessID == self.pid {
                    self.thread_list.push(thread_entry.th32ThreadID);
                }
                let success = Thread32Next(snapshot, &mut thread_entry);
            }
            CloseHandle(snapshot);
        }
    }
    fn debug_set_process_kill_on_exit(&mut self) {
        unsafe {
            DebugSetProcessKillOnExit(true);
        }
    }
    fn terminate_process(&mut self, h_process: HANDLE) {
        let exit_code = 0;
        unsafe {
            if TerminateProcess(h_process, exit_code).as_bool() == true {
                println!(
                    "[+] Process {} terminated successfuly!",
                    self.get_process_id(h_process)
                );
            } else {
                println!("[-] TerminateProcess failed!");
            }
        }
    }
    fn get_process_id(&mut self, h_process: HANDLE) -> u32 {
        unsafe {
            let pid = GetProcessId(h_process);
            if pid == 0 {
                println!("[-] Failed to get Process ID");
                pid
            } else {
                println!("[+] Process ID is: {}", pid);
                pid
            }
        }
    }
    fn get_hash(&mut self, input: usize) -> String{
        let mut hasher = Sha256::new();
        hasher.update(input.to_string());
        let result = hasher.finalize();
        let mut temp = String::new();
        for i in result.iter() {
            temp.push_str(&format!("{:x}", i));
        }        
        temp
    }

    fn detach(&mut self) {
        unsafe {
            if DebugActiveProcessStop(self.pid).as_bool() == true {
                println!("[+] Detached successfully!");
                self.debugger_active = false;
            } else {
                println!("[-] An error occurred while detaching");
            }
        }
    }
}


fn serve_tcp_server(cs: Arc<CrashStatus>) {
    let listener = TcpListener::bind("0.0.0.0:4444").unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        
        let current_crash_status: String =  cs.as_ref().crash_status.load(Ordering::SeqCst).to_string();
                    
        println!("Current Crash Status: {}", current_crash_status);
        stream.write(current_crash_status.as_bytes()).unwrap();

        if current_crash_status == "1" {
            // TODO implement better synchronization

            // sleep 3 seconds
            thread::sleep(Duration::from_secs(3));
        }
        cs.crash_status.store(0, Ordering::SeqCst);
        drop(stream);
    }
}

fn main() {

    let debugee = Debugee::default();
    
    let mut input = String::new();
    println!("Enter process path");
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to get input");
    let input = input.trim();
    println!("Your input: {}", input);
    let mut debugee = Debugee::default();

    let cs = Arc::new(CrashStatus::default()); 
    let mut cs_clone = &cs.clone();

    let handle = thread::spawn(move || serve_tcp_server(cs));
    
    loop {
        let process = Command::new(input).spawn().expect("Failed to run program");
        let pid = process.id();
        println!("Process ID: {}", pid);
        debugee.attach_process(pid);
        debugee.run(cs_clone);
    }
}
