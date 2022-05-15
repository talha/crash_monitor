#[allow(unused_imports)]
use std::ffi::c_void;
use std::io;
use std::path::Path;
use std::ptr;
use windows::{
    core::*, Win32::Foundation::*, Win32::System::Threading::*, Win32::System::Diagnostics::Debug::*,
    Win32::UI::WindowsAndMessaging::*, Data::Xml::Dom::*, Win32::System::LibraryLoader::*, Win32::Security::*,
};
use std::time::Duration;
use std::thread::sleep;
use std::ffi::CString;

const CONTEXT_FULL: u32 = 0x00010007;
const CONTEXT_DEBUG_REGISTERS: u32 = 0x00010010;

#[derive(Debug)]
struct Debugee {
    h_process: HANDLE,
    pid: u32,
    debugger_active: bool,
    h_thread: HANDLE,
    context: WOW64_CONTEXT, // ?
    exception: NTSTATUS,
    exception_address: *mut c_void,
}

pub trait Debugger {
    fn run(&mut self);
    fn load(&mut self, path_to_binary: String) -> u32;
    fn create_process(&mut self) -> u32;
    fn open_process(&mut self, pid: u32) -> HANDLE;
    fn attach_process(&mut self, pid: u32);
    fn debug_handler(&mut self) -> u32;
    fn open_thread(&mut self, thread_id: u32) -> HANDLE;
    fn thread_context(&mut self, thread_id: u32, h_thread: HANDLE) -> WOW64_CONTEXT;
    fn function_resolve(&mut self, dll: PCSTR, function: PCSTR);
    fn detach(&mut self);
}

impl Default for Debugee {
    fn default() -> Debugee {
        Debugee {
            h_process: Default::default(),
            pid: 0,
            debugger_active: false,
            h_thread: Default::default(),
            context: WOW64_CONTEXT::default(), // ?
            exception: NTSTATUS::default(),
            exception_address: std::ptr::null_mut(),
        }
    }
}

impl Debugger for Debugee {
    fn run(&mut self) {
        while self.debugger_active == true {
            self.debug_handler();
        }
    }

    fn load(&mut self, path_to_binary: String) -> u32 {
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
            let process = CreateProcessA(PCSTR(path_to_binary),
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
        0
    }
    fn create_process(&mut self) -> u32 {
        todo!()
    }
    fn open_process(&mut self, pid: u32) -> HANDLE {
        unsafe {
            let handle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, false, pid).expect("Failed to open the process");
            println!("[+] OpenProcess is successful!");
            handle
        }
    }
    fn attach_process(&mut self, pid: u32) {
        unsafe {
            // TODO check bitness of debugee and debugger
            println!("[*] Attaching process: {}", pid);
            self.h_process = self.open_process(pid);
            let mut temp = String::new();
            println!("Enter:");
            io::stdin().read_line(&mut temp).unwrap();
            println!("[*] Trying to Debug Active Process");
            if DebugActiveProcess(pid).as_bool() == true {
                self.debugger_active = true;
                self.pid = pid;
                println!("[+] Debugging active process!");
            }
            else {
                println!("[-] Unable to attach to the process.");
                let win32_error = GetLastError();
                println!("WIN32_ERROR: {:?}, Error message: {:?}", win32_error, win32_error.to_hresult().message());
            }
        }
    }
    fn debug_handler(&mut self) -> u32 { // get_debug_event
        unsafe {
            let mut debug_event = DEBUG_EVENT::default();

            //let debug_event = 
            let continue_status = DBG_CONTINUE;

            if WaitForDebugEvent(&mut debug_event, 100).as_bool() == true {

                self.h_thread = self.open_thread(debug_event.dwThreadId);
                println!("Event Code: {:?}, Thread ID: {}", debug_event.dwDebugEventCode, debug_event.dwThreadId);


                //self.context = self.thread_context(thread_id: u32, h_thread: HANDLE)
                if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
                    self.exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
                    self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;

                    println!("Exception: {:?}, Exception Address: {:?}", self.exception, self.exception_address);

                    if self.exception == EXCEPTION_ACCESS_VIOLATION {
                        println!("Access Violation Detected.");
                        std::process::exit(1);
                        // save the crash
                    }
                    if self.exception == EXCEPTION_BREAKPOINT {
                        println!("EXCEPTION_BREAKPOINT");
                    }
                    if self.exception == EXCEPTION_GUARD_PAGE {
                        println!("EXCEPTION_GUARD_PAGE");
                    }
                    if self.exception == EXCEPTION_SINGLE_STEP {
                        println!("EXCEPTION_SINGLE_STEP");
                    }
                }
                ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status.0.try_into().unwrap());
            }
        }
        0
    }
    fn open_thread(&mut self, thread_id: u32) -> HANDLE {
        unsafe {
            let handle: HANDLE = OpenThread(THREAD_ALL_ACCESS, None, thread_id).unwrap();
            if handle.is_invalid() == true {
                println!("[*] Could not obtain a valid thread handle");
                HANDLE(-1)
            }
            else{
                self.h_thread
            }
        }
    }
    fn thread_context(&mut self, thread_id: u32, h_thread: HANDLE) -> WOW64_CONTEXT {
        unsafe {
            let mut context = WOW64_CONTEXT{ContextFlags: CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS, ..Default::default()};
            
            if h_thread.is_invalid() == true {
                self.h_thread = self.open_process(thread_id);
            }
            if Wow64GetThreadContext(self.h_thread, &mut context).as_bool() == true {
                println!("[+] Got thread context");
                context
            }
            else {
                println!("[*] Failed to get thread context!");
                WOW64_CONTEXT::default()
            }
        }
    }
    fn detach(&mut self) {
        unsafe {
            if DebugActiveProcessStop(self.pid).as_bool() == true {
                println!("[+] Detached successfully!");
            }
            else{
                println!("[-] An error occurred while detaching");
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
}

fn main() -> io::Result<()> {
    let mut x = Debugee {
        ..Default::default()
    };
    let mut calc_exe = r"C:\win7calc\calc.exe".to_string();

    let mut pid = String::new();
    println!("Enter process id to attach:");
    io::stdin().read_line(&mut pid).expect("Enter an integer");
    let pid: u32 = pid.trim().parse().unwrap();
    println!("You have entered: {}", pid);
    x.attach_process(pid);
    //x.load(calc_exe);
    x.run();
    Ok(())
}
