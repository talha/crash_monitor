use crate::types::HANDLE;

extern "stdcall" {
    pub fn CreateProcessA (
        lpApplicationName: crate::types::LPCSTR,
        lpCommandLine: crate::types::LPSTR,
        lpProcessAttributes: crate::structs::LPSECURITY_ATTRIBUTES,
        lpThreadAttributes: crate::structs::LPSECURITY_ATTRIBUTES,
        bInheritHandles: crate::types::BOOL,
        dwCreationFlags: crate::types::DWORD,
        lpEnvironment: crate::types::LPVOID,
        lpCurrentDirectory: crate::types::LPCSTR,
        lpStartupInfo: crate::types::LPSTARTUPINFOA,
        lpProcessInformation: crate::types::LPPROCESS_INFORMATION,
    ) -> crate::types::BOOL;

    pub fn WaitForSingleObject(
        hHandle: crate::types::HANDLE,
        dwMilliseconds: crate::types::DWORD,
    ) -> crate::types::DWORD;
}
