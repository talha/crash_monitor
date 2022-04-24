pub type SECURITY_ATTRIBUTES = crate::types::PVOID;
pub type LPSECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES;

#[repr(C)]
pub struct STARTUPINFOA {
    pub cb: crate::types::DWORD,
    pub lpReserved: crate::types::LPSTR,
    pub lpDesktop: crate::types::LPSTR,
    pub lpTitle: crate::types::LPSTR,
    pub dwX: crate::types::DWORD,
    pub dwY: crate::types::DWORD,
    pub dwXSize: crate::types::DWORD,
    pub dwYSize: crate::types::DWORD,
    pub dwXCountChars: crate::types::DWORD,
    pub dwYCountChars: crate::types::DWORD,
    pub dwFillAttribute: crate::types::DWORD,
    pub dwFlags: crate::types::DWORD,
    pub wShowWindow: crate::types::WORD,
    pub cbReserved2: crate::types::WORD,
    pub lpReserved2: crate::types::LPBYTE,
    pub hStdInput: crate::types::HANDLE,
    pub hStdOutput: crate::types::HANDLE,
    pub hStdError: crate::types::HANDLE,
}

#[repr(C)]
pub struct PROCESS_INFORMATION {
    pub hProcess: crate::types::HANDLE,
    pub hThread: crate::types::HANDLE,
    pub dwProcessId: crate::types::DWORD,
    pub dwThreadId: crate::types::DWORD,
}
