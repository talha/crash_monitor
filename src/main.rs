use std::ffi::c_void;
use std::{cmp, io, mem};
use std::path::Path;
use std::process::{Command, exit, ExitStatus};
use std::ptr;
use windows::{
    core::*, Data::Xml::Dom::*, Win32::Foundation::*, Win32::System::Threading::*,
    Win32::UI::WindowsAndMessaging::*
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use std::time::Duration;
use std::thread::sleep;

// Trait std::os::windows::process::ExitStatusExt
// https://grep.app/search?q=std%3A%3Aos%3A%3Awindows%3A%3Aprocess%3A%3AExitStatusExt

fn monitor(process_name: String) -> io::Result<ExitStatus> {
    let monitor = Command::new(process_name).output()?;
    println!("Output: {:#?}", monitor);

    Ok(monitor.status)
}

fn call_monitor() -> io::Result<()> {
    let process_name = r"C:\Users\zet\Desktop\vulnserver\vulnserver.exe".to_string();
    println!("{}", process_name);
    let exit_code = monitor(process_name);
    println!("Exit Code: {:?}", exit_code);
    Ok(())
}
/*
fn call_messagebox() {
    let title = CString::new(r"this is title").unwrap();
    let message = CString::new(r"this is message").unwrap();
    unsafe {
        MessageBoxA(null_mut(), message.as_ptr(), title.as_ptr(),
                    winapi::um::winuser::MB_OK | winapi::um::winuser::MB_ICONINFORMATION);
    }
}
*/

fn main() -> io::Result<()> {
    // run calc.exe
    let mut calc_exe = PCSTR("C:\\Windows\\System32\\calc.exe\0".as_ptr());
    let creation_fags = DEBUG_PROCESS; // DEBUG_FLAG
    let mut startupinfo = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        lpReserved: PSTR(ptr::null_mut()),
        lpDesktop: PSTR(ptr::null_mut()),
        lpTitle: PSTR(ptr::null_mut()),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: STARTUPINFOW_FLAGS(0x1),
        wShowWindow: 0x0,
        cbReserved2: 0,
        lpReserved2: ptr::null_mut(),
        hStdInput: HANDLE(0),
        hStdOutput: HANDLE(0),
        hStdError: HANDLE(0),
    };

    let mut process_information = PROCESS_INFORMATION {
        hProcess: HANDLE(0),
        hThread: HANDLE(0),
        dwProcessId: 0,
        dwThreadId: 0,
    };
    unsafe {
        let process = CreateProcessA(calc_exe,
                                     PSTR(ptr::null_mut()),
                                     ptr::null(),
                                     ptr::null(),
                                     BOOL(0),
                                     creation_fags,
                                     0 as *mut c_void,
                                     PCSTR(ptr::null_mut()),
                                     &mut startupinfo,
                                     &mut process_information,
        );
        if process.0 != 0 {
            print!("[*] We have successfully launched the process!\n");
            print!("[*] The Process ID of running process is: {}\n", process_information.dwProcessId);
            //sleep(Duration::from_secs(10));
            WaitForSingleObject(process_information.hProcess, 0xFFFFFFFF);
        }
    }
    Ok(())
}
