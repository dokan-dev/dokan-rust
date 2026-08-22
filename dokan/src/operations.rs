use std::{ptr::NonNull, slice};

use dokan_sys::{
	ACCESS_MASK, BOOL, DWORD, FILETIME, LONGLONG, LPBY_HANDLE_FILE_INFORMATION, LPCVOID, LPCWSTR,
	LPDWORD, LPVOID, LPWSTR, NTSTATUS, PDOKAN_FILE_INFO, PDOKAN_IO_SECURITY_CONTEXT, PFillFindData,
	PFillFindStreamData, PSECURITY_DESCRIPTOR, PSECURITY_INFORMATION, PULONG, PULONGLONG, PVOID,
	ULONG,
	win32::{FILE_OPEN_IF, FILE_OVERWRITE_IF, FILE_SUPERSEDE},
};
use widestring::U16CStr;

use crate::{
	CreateDisposition, CreateOptions, FileAttributes, SecurityContext, SecurityInformation,
	ShareAccess,
	data::{DirectoryFiller, FileTimeOperation, OperationInfo, StreamFiller},
	file_system_handler::{CreateFileRequest, FileSystemHandler},
	operations_helpers::{NtResult, wrap_nt_result, wrap_unit},
	status,
};

const TRUE: i32 = 1;
const STATUS_BUFFER_OVERFLOW: crate::NtStatus = status::BUFFER_OVERFLOW;
const STATUS_INVALID_PARAMETER: crate::NtStatus = status::INVALID_PARAMETER;
const STATUS_OBJECT_NAME_COLLISION: crate::NtStatus = status::OBJECT_NAME_COLLISION;

pub extern "system" fn create_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	security_context: PDOKAN_IO_SECURITY_CONTEXT,
	desired_access: ACCESS_MASK,
	file_attributes: ULONG,
	share_access: ULONG,
	create_disposition: ULONG,
	create_options: ULONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut info = OperationInfo::<FSH>::new(dokan_file_info);
		info.drop_context();
		let disposition = CreateDisposition::try_from(create_disposition)
			.map_err(|_| STATUS_INVALID_PARAMETER)?;
		let request = CreateFileRequest {
			path: file_name,
			security: SecurityContext::new(&*security_context),
			desired_access: crate::AccessRights::from_bits_retain(desired_access),
			file_attributes: FileAttributes::from_bits_retain(file_attributes),
			share_access: ShareAccess::from_bits_retain(share_access),
			disposition,
			options: CreateOptions::from_bits_retain(create_options),
			operation: &info,
		};
		info.handler()
			.create_file(&request)
			.and_then(|create_info| {
				(*dokan_file_info).Context = Box::into_raw(Box::new(create_info.context)) as u64;
				(*dokan_file_info).IsDirectory = create_info.is_dir.into();
				if (create_disposition == FILE_OPEN_IF
					|| create_disposition == FILE_OVERWRITE_IF
					|| create_disposition == FILE_SUPERSEDE)
					&& !create_info.new_file_created
				{
					Err(STATUS_OBJECT_NAME_COLLISION)
				} else {
					Ok(())
				}
			})
	})
}

pub extern "system" fn cleanup<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) {
	wrap_unit(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		if let Ok(context) = info.context() {
			info.handler().cleanup(file_name, &info, context);
		}
	});
}

pub extern "system" fn close_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) {
	let mut info = OperationInfo::<FSH>::new(dokan_file_info);
	wrap_unit(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		if let Ok(context) = info.context() {
			info.handler().close_file(file_name, &info, context);
		}
	});
	// Context destruction must happen even when user code panics.
	info.drop_context();
}

pub extern "system" fn read_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	buffer: LPVOID,
	buffer_length: DWORD,
	read_length: LPDWORD,
	offset: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		*read_length = 0;
		let file_name = U16CStr::from_ptr_str(file_name);
		let offset = u64::try_from(offset).map_err(|_| STATUS_INVALID_PARAMETER)?;
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let buffer: &mut [u8] = if buffer_length == 0 {
			&mut []
		} else {
			let buffer = NonNull::new(buffer.cast::<u8>()).ok_or(STATUS_INVALID_PARAMETER)?;
			slice::from_raw_parts_mut(buffer.as_ptr(), buffer_length as usize)
		};
		info.handler()
			.read_file(file_name, offset, buffer, &info, info.context()?)
			.and_then(|bytes_read| {
				if bytes_read > buffer_length {
					Err(STATUS_INVALID_PARAMETER)
				} else {
					*read_length = bytes_read;
					Ok(())
				}
			})
	})
}

pub extern "system" fn write_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	buffer: LPCVOID,
	number_of_bytes_to_write: DWORD,
	number_of_bytes_written: LPDWORD,
	offset: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		*number_of_bytes_written = 0;
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let buffer: &[u8] = if number_of_bytes_to_write == 0 {
			&[]
		} else {
			let buffer =
				NonNull::new(buffer.cast_mut().cast::<u8>()).ok_or(STATUS_INVALID_PARAMETER)?;
			slice::from_raw_parts(buffer.as_ptr(), number_of_bytes_to_write as usize)
		};
		info.handler()
			.write_file(file_name, offset, buffer, &info, info.context()?)
			.and_then(|bytes_written| {
				if bytes_written > number_of_bytes_to_write {
					Err(STATUS_INVALID_PARAMETER)
				} else {
					*number_of_bytes_written = bytes_written;
					Ok(())
				}
			})
	})
}

pub extern "system" fn flush_file_buffers<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.flush_file_buffers(file_name, &info, info.context()?)
	})
}

pub extern "system" fn get_file_information<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	buffer: LPBY_HANDLE_FILE_INFORMATION,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.get_file_information(file_name, &info, info.context()?)
			.map(|file_info| {
				*buffer = file_info.to_raw_struct();
			})
	})
}

pub extern "system" fn find_files<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	fill_find_data: PFillFindData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut filler = DirectoryFiller::new(fill_find_data, dokan_file_info)
			.ok_or(STATUS_INVALID_PARAMETER)?;
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let result = info
			.handler()
			.find_files(file_name, &mut filler, &info, info.context()?);
		if result.is_ok() && filler.is_full() {
			Err(STATUS_BUFFER_OVERFLOW)
		} else {
			result
		}
	})
}

pub extern "system" fn find_files_with_pattern<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	search_pattern: LPCWSTR,
	fill_find_data: PFillFindData,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let search_pattern = U16CStr::from_ptr_str(search_pattern);
		let mut filler = DirectoryFiller::new(fill_find_data, dokan_file_info)
			.ok_or(STATUS_INVALID_PARAMETER)?;
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let result = info.handler().find_files_with_pattern(
			file_name,
			search_pattern,
			&mut filler,
			&info,
			info.context()?,
		);
		if result.is_ok() && filler.is_full() {
			Err(STATUS_BUFFER_OVERFLOW)
		} else {
			result
		}
	})
}

pub extern "system" fn set_file_attributes<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	file_attributes: DWORD,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler().set_file_attributes(
			file_name,
			FileAttributes::from_bits_retain(file_attributes),
			&info,
			info.context()?,
		)
	})
}

pub extern "system" fn set_file_time<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	creation_time: *const FILETIME,
	last_access_time: *const FILETIME,
	last_write_time: *const FILETIME,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler().set_file_time(
			file_name,
			FileTimeOperation::from_raw(creation_time),
			FileTimeOperation::from_raw(last_access_time),
			FileTimeOperation::from_raw(last_write_time),
			&info,
			info.context()?,
		)
	})
}

pub extern "system" fn delete_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.delete_file(file_name, &info, info.context()?)
	})
}

pub extern "system" fn delete_directory<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.delete_directory(file_name, &info, info.context()?)
	})
}

pub extern "system" fn move_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	new_file_name: LPCWSTR,
	replace_if_existing: BOOL,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let new_file_name = U16CStr::from_ptr_str(new_file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler().move_file(
			file_name,
			new_file_name,
			replace_if_existing == TRUE,
			&info,
			info.context()?,
		)
	})
}

pub extern "system" fn set_end_of_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.set_end_of_file(file_name, byte_offset, &info, info.context()?)
	})
}

pub extern "system" fn set_allocation_size<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	alloc_size: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.set_allocation_size(file_name, alloc_size, &info, info.context()?)
	})
}

type LockOperation<FSH> = fn(
	&FSH,
	&U16CStr,
	i64,
	i64,
	&OperationInfo<'_, FSH>,
	&<FSH as FileSystemHandler>::Context,
) -> NtResult;

// Extern system functions with similar bodies but not called directly can trigger a compiler bug when built in
// release mode. It seems that extracting the function bodies into a common function works around this bug.
// See https://github.com/rust-lang/rust/issues/72212
fn lock_unlock_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	length: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
	func: LockOperation<FSH>,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		func(
			info.handler(),
			file_name,
			byte_offset,
			length,
			&info,
			info.context()?,
		)
	})
}

pub extern "system" fn lock_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	length: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	lock_unlock_file(
		file_name,
		byte_offset,
		length,
		dokan_file_info,
		FSH::lock_file,
	)
}

pub extern "system" fn unlock_file<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	byte_offset: LONGLONG,
	length: LONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	lock_unlock_file(
		file_name,
		byte_offset,
		length,
		dokan_file_info,
		FSH::unlock_file,
	)
}

pub extern "system" fn get_disk_free_space<FSH: FileSystemHandler>(
	free_bytes_available: PULONGLONG,
	total_number_of_bytes: PULONGLONG,
	total_number_of_free_bytes: PULONGLONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| {
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.get_disk_free_space(&info)
			.map(|space_info| unsafe {
				if !free_bytes_available.is_null() {
					*free_bytes_available = space_info.available_byte_count;
				}
				if !total_number_of_bytes.is_null() {
					*total_number_of_bytes = space_info.byte_count;
				}
				if !total_number_of_free_bytes.is_null() {
					*total_number_of_free_bytes = space_info.free_byte_count;
				}
			})
	})
}

pub extern "system" fn get_volume_information<FSH: FileSystemHandler>(
	volume_name_buffer: LPWSTR,
	volume_name_size: DWORD,
	volume_serial_number: LPDWORD,
	maximum_component_length: LPDWORD,
	file_system_flags: LPDWORD,
	file_system_name_buffer: LPWSTR,
	file_system_name_size: DWORD,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| {
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler()
			.get_volume_information(&info)
			.and_then(|volume_info| unsafe {
				if !volume_name_buffer.is_null() && volume_name_size != 0 {
					let buffer =
						slice::from_raw_parts_mut(volume_name_buffer, volume_name_size as usize);
					volume_info
						.name
						.copy_truncated(buffer)
						.map_err(|_| STATUS_INVALID_PARAMETER)?;
				}
				if !volume_serial_number.is_null() {
					*volume_serial_number = volume_info.serial_number;
				}
				if !maximum_component_length.is_null() {
					*maximum_component_length = volume_info.max_component_length;
				}
				if !file_system_flags.is_null() {
					*file_system_flags = volume_info.features.bits();
				}
				if !file_system_name_buffer.is_null() && file_system_name_size != 0 {
					let buffer = slice::from_raw_parts_mut(
						file_system_name_buffer,
						file_system_name_size as usize,
					);
					volume_info
						.fs_name
						.copy_truncated(buffer)
						.map_err(|_| STATUS_INVALID_PARAMETER)?;
				}
				Ok(())
			})
	})
}

pub extern "system" fn mounted<FSH: FileSystemHandler>(
	mount_point: LPCWSTR,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let mount_point = U16CStr::from_ptr_str(mount_point);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler().mounted(mount_point, &info)
	})
}

pub extern "system" fn unmounted<FSH: FileSystemHandler>(
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| {
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		info.handler().unmounted(&info)
	})
}

pub extern "system" fn get_file_security<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	security_information: PSECURITY_INFORMATION,
	security_descriptor: PSECURITY_DESCRIPTOR,
	buffer_length: ULONG,
	length_needed: PULONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let descriptor_ptr = if buffer_length == 0 {
			NonNull::<u8>::dangling().as_ptr()
		} else {
			NonNull::new(security_descriptor.cast::<u8>())
				.ok_or(STATUS_INVALID_PARAMETER)?
				.as_ptr()
		};
		let descriptor = slice::from_raw_parts_mut(descriptor_ptr, buffer_length as usize);
		info.handler()
			.get_file_security(
				file_name,
				SecurityInformation::from_bits_retain(*security_information),
				descriptor,
				&info,
				info.context()?,
			)
			.and_then(|needed| {
				*length_needed = needed.try_into().map_err(|_| STATUS_INVALID_PARAMETER)?;
				if needed <= buffer_length as usize {
					Ok(())
				} else {
					Err(STATUS_BUFFER_OVERFLOW)
				}
			})
	})
}

pub extern "system" fn set_file_security<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	security_information: PSECURITY_INFORMATION,
	security_descriptor: PSECURITY_DESCRIPTOR,
	buffer_length: ULONG,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let descriptor_ptr = if buffer_length == 0 {
			NonNull::<u8>::dangling().as_ptr()
		} else {
			NonNull::new(security_descriptor.cast::<u8>())
				.ok_or(STATUS_INVALID_PARAMETER)?
				.as_ptr()
		};
		let descriptor = slice::from_raw_parts(descriptor_ptr, buffer_length as usize);
		info.handler().set_file_security(
			file_name,
			SecurityInformation::from_bits_retain(*security_information),
			descriptor,
			&info,
			info.context()?,
		)
	})
}

pub extern "system" fn find_streams<FSH: FileSystemHandler>(
	file_name: LPCWSTR,
	fill_find_stream_data: PFillFindStreamData,
	find_stream_context: PVOID,
	dokan_file_info: PDOKAN_FILE_INFO,
) -> NTSTATUS {
	wrap_nt_result(|| unsafe {
		let file_name = U16CStr::from_ptr_str(file_name);
		let mut filler = StreamFiller::new(fill_find_stream_data, find_stream_context)
			.ok_or(STATUS_INVALID_PARAMETER)?;
		let info = OperationInfo::<FSH>::new(dokan_file_info);
		let result = info
			.handler()
			.find_streams(file_name, &mut filler, &info, info.context()?);
		if result.is_ok() && filler.is_full() {
			Err(STATUS_BUFFER_OVERFLOW)
		} else {
			result
		}
	})
}
