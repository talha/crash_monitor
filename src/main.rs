use std::io;
use std::path::Path;
use std::process::{Command, exit, ExitStatus};

use windows_sys::{
    Win32::Foundation::*, Win32::System::Threading::*, Win32::UI::WindowsAndMessaging::*
};
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
    let mut calc_exe = b"C:\\Windows\\System32\\calc.exe\0";
    let creation_fags = DEBUG_PROCESS; // DEBUG_FLAG
    let mut startupinfo = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as u32,
        lpReserved: std::ptr::null_mut(),
        lpDesktop: std::ptr::null_mut(),
        lpTitle: std::ptr::null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: 0x1,
        wShowWindow: 0x0,
        cbReserved2: 0,
        lpReserved2: std::ptr::null_mut(),
        hStdInput: 0,
        hStdOutput: 0,
        hStdError: 0,
    };

    let mut process_information = PROCESS_INFORMATION {
        hProcess: isize,
        hThread: NULL as HANDLE,
        dwProcessId: 0,
        dwThreadId: 0,
    };
    unsafe {
        let process = CreateProcessA(calc_exe,
                                     NULL as LPSTR,
                                     std::ptr::null_mut(),
                                     std::ptr::null_mut(),
                                     0,
                                     creation_fags,
                                     NULL,
                                     NULL as LPCSTR,
                                     &mut startupinfo,
                                     &mut process_information,
        );
        if process != 0 {
            print!("[*] We have successfully launched the process!");
            print!("[*] The Process ID of running process is: {}", process_information.dwProcessId);
            WaitForSingleObject(process_information.hProcess, INFINITE);
        }
    }

    Ok(())
}
