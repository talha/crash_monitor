#![allow(non_snake_case)]
#![allow(dead_code)]
#![allow(non_camel_case_types)]
#![allow(unused)]
mod enums;
mod types;
mod structs;
mod functions;

extern crate winapi;

use std::io;
use std::path::Path;
use std::process::{Command, exit, ExitStatus};
use winapi::um::winnt::{LPCSTR};
use std::ffi::{CStr, CString};
use std::ptr::null_mut;
use winapi::ctypes::c_ulong;
use winapi::um::winuser::{MessageBoxA};
use winapi::um::winbase::{DEBUG_PROCESS};
use winapi::shared::minwindef::{LPBYTE, WORD, DWORD};
use winapi::um::winnt::{HANDLE, LPSTR};
use winapi::um::winbase::{INFINITE};
use structs::{PROCESS_INFORMATION, STARTUPINFOA};
use enums::NULL;
use functions::{CreateProcessA, WaitForSingleObject};

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

fn call_messagebox() {
    let title = CString::new(r"this is title").unwrap();
    let message = CString::new(r"this is message").unwrap();
    unsafe {
        MessageBoxA(null_mut(), message.as_ptr(), title.as_ptr(),
                    winapi::um::winuser::MB_OK | winapi::um::winuser::MB_ICONINFORMATION);
    }
}

fn main() -> io::Result<()> {
    // run calc.exe
    let calc_exe = CString::new(r"C:\Windows\System32\calc.exe").unwrap().into_raw();
    let creation_fags = DEBUG_PROCESS; // DEBUG_FLAG
    let mut startupinfo = STARTUPINFOA {
        cb: std::mem::size_of::<STARTUPINFOA>() as DWORD,
        lpReserved: NULL as LPSTR,
        lpDesktop: NULL as LPSTR,
        lpTitle: NULL as LPSTR,
        dwX: 0 as DWORD,
        dwY: 0 as DWORD,
        dwXSize: 0 as DWORD,
        dwYSize: 0 as DWORD,
        dwXCountChars: 0 as DWORD,
        dwYCountChars: 0 as DWORD,
        dwFillAttribute: 0 as DWORD,
        dwFlags: 0x1 as DWORD,
        wShowWindow: 0x0 as WORD,
        cbReserved2: NULL as WORD,
        lpReserved2: NULL as LPBYTE,
        hStdInput: NULL,
        hStdOutput: NULL,
        hStdError: NULL,
    };

    let mut process_information = PROCESS_INFORMATION {
        hProcess: NULL,
        hThread: NULL,
        dwProcessId: 0,
        dwThreadId: 0,
    };
    unsafe {
        let process = CreateProcessA(calc_exe,
                                     NULL as crate::types::LPSTR,
                                     NULL,
                                     NULL,
                                     0,
                                     creation_fags,
                                     NULL,
                                     NULL as crate::types::LPCSTR,
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
