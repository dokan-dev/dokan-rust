use dokan::OperationError;
use winapi::shared::ntdef;
use winapi::um::errhandlingapi;

pub fn nt_err(stat: ntdef::NTSTATUS) -> OperationError {
	OperationError::NtStatus(stat)
}

pub fn nt_res<T>(stat: ntdef::NTSTATUS) -> Result<T, OperationError> {
	Err(nt_err(stat))
}

fn win32_last_err() -> OperationError {
	unsafe { OperationError::Win32(errhandlingapi::GetLastError()) }
}

pub fn win32_last_res<T>() -> Result<T, OperationError> {
	Err(win32_last_err())
}
