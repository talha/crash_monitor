pub type INT8 = i8;
pub type INT16 = i16;
pub type INT32 = i32;
pub type INT64 = i64;

pub type UINT8 = u8;
pub type UINT16 = u16;
pub type UINT32 = u32;
pub type UINT64 = u64;

pub type BYTE = UINT8;
pub type WORD = UINT16;
pub type DWORD = UINT32;
pub type QWORD = UINT64;

pub type CCHAR = INT8;
pub type CHAR = INT8;
pub type SHORT = INT16;
pub type LONG = INT32;
pub type LONGLONG = INT64;

pub type UCHAR = UINT8;
pub type USHORT = UINT16;
pub type ULONG = UINT32;
pub type ULONGLONG = UINT64;

pub type PULONG = *mut ULONG;

pub type SIZE_T = usize;
pub type SSIZE_T = isize;

pub type PSIZE_T = *mut SIZE_T;
pub type PSSIZE_T = *mut SSIZE_T;

pub type BOOLEAN = u8;
pub type PBOOLEAN = *mut BOOLEAN;

pub type BOOL = u32;
pub type PBOOL = *mut BOOL;

pub type PWSTR = *mut u16;
pub type PVOID = *mut usize;
pub type PCHAR = *mut i8;

pub type HANDLE = PVOID;
pub type PHANDLE = *mut PVOID;

pub type LPSTR = *mut CHAR;
pub type LPBYTE = *mut BYTE;
