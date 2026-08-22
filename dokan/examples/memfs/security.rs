use std::{mem, ptr};

use dokan::{
	OperationResult, map_win32_error_to_ntstatus, status::STATUS_INVALID_PARAMETER, win32_ensure,
};
use winapi::{
	shared::{minwindef, ntdef, winerror},
	um::{errhandlingapi::GetLastError, heapapi, securitybaseapi, winnt},
};

#[derive(Debug)]
struct AlignedBuffer {
	words: Box<[usize]>,
	len: usize,
}

impl AlignedBuffer {
	fn zeroed(len: usize) -> Self {
		let word_count = len.div_ceil(mem::size_of::<usize>());
		Self {
			words: vec![0; word_count].into_boxed_slice(),
			len,
		}
	}

	fn len(&self) -> usize {
		self.len
	}

	fn as_mut_sid(&mut self) -> winnt::PSID {
		self.words.as_mut_ptr().cast()
	}

	fn as_mut_acl(&mut self) -> winnt::PACL {
		self.words.as_mut_ptr().cast()
	}
}

#[derive(Debug)]
struct PrivateObjectSecurity {
	value: winnt::PSECURITY_DESCRIPTOR,
}

impl PrivateObjectSecurity {
	unsafe fn from_raw(ptr: winnt::PSECURITY_DESCRIPTOR) -> Self {
		Self { value: ptr }
	}
}

impl Drop for PrivateObjectSecurity {
	fn drop(&mut self) {
		unsafe {
			securitybaseapi::DestroyPrivateObjectSecurity(&raw mut self.value);
		}
	}
}

#[derive(Debug)]
pub struct SecurityDescriptor {
	desc_ptr: winnt::PSECURITY_DESCRIPTOR,
}

unsafe impl Sync for SecurityDescriptor {}

unsafe impl Send for SecurityDescriptor {}

fn get_well_known_sid(sid_type: winnt::WELL_KNOWN_SID_TYPE) -> OperationResult<AlignedBuffer> {
	unsafe {
		let mut sid =
			AlignedBuffer::zeroed(mem::size_of::<winnt::SID>() + mem::size_of::<u32>() * 7);
		let mut len = u32::try_from(sid.len()).expect("a Windows SID is smaller than u32::MAX");
		win32_ensure(
			securitybaseapi::CreateWellKnownSid(
				sid_type,
				ptr::null_mut(),
				sid.as_mut_sid(),
				&raw mut len,
			) == minwindef::TRUE,
		)?;
		Ok(sid)
	}
}

fn create_default_dacl() -> OperationResult<AlignedBuffer> {
	unsafe {
		let admins_sid = get_well_known_sid(winnt::WinBuiltinAdministratorsSid)?;
		let system_sid = get_well_known_sid(winnt::WinLocalSystemSid)?;
		let auth_sid = get_well_known_sid(winnt::WinAuthenticatedUserSid)?;
		let users_sid = get_well_known_sid(winnt::WinBuiltinUsersSid)?;

		let acl_len = mem::size_of::<winnt::ACL>()
			+ (mem::size_of::<winnt::ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>()) * 4
			+ admins_sid.len()
			+ system_sid.len()
			+ auth_sid.len()
			+ users_sid.len();
		let mut acl = AlignedBuffer::zeroed(acl_len);
		win32_ensure(
			securitybaseapi::InitializeAcl(
				acl.as_mut_acl(),
				u32::try_from(acl_len).expect("the default ACL is smaller than u32::MAX"),
				u32::from(winnt::ACL_REVISION),
			) == minwindef::TRUE,
		)?;

		let flags = u32::from(winnt::CONTAINER_INHERIT_ACE | winnt::OBJECT_INHERIT_ACE);
		win32_ensure(
			securitybaseapi::AddAccessAllowedAceEx(
				acl.as_mut_acl(),
				u32::from(winnt::ACL_REVISION),
				flags,
				winnt::FILE_ALL_ACCESS,
				admins_sid.words.as_ptr().cast_mut().cast(),
			) == minwindef::TRUE,
		)?;

		win32_ensure(
			securitybaseapi::AddAccessAllowedAceEx(
				acl.as_mut_acl(),
				u32::from(winnt::ACL_REVISION),
				flags,
				winnt::FILE_ALL_ACCESS,
				system_sid.words.as_ptr().cast_mut().cast(),
			) == minwindef::TRUE,
		)?;

		win32_ensure(
			securitybaseapi::AddAccessAllowedAceEx(
				acl.as_mut_acl(),
				u32::from(winnt::ACL_REVISION),
				flags,
				winnt::FILE_GENERIC_READ
					| winnt::FILE_GENERIC_WRITE
					| winnt::FILE_GENERIC_EXECUTE
					| winnt::DELETE,
				auth_sid.words.as_ptr().cast_mut().cast(),
			) == minwindef::TRUE,
		)?;

		win32_ensure(
			securitybaseapi::AddAccessAllowedAceEx(
				acl.as_mut_acl(),
				u32::from(winnt::ACL_REVISION),
				flags,
				winnt::FILE_GENERIC_READ | winnt::FILE_GENERIC_EXECUTE,
				users_sid.words.as_ptr().cast_mut().cast(),
			) == minwindef::TRUE,
		)?;

		Ok(acl)
	}
}

const FILE_GENERIC_MAPPING: winnt::GENERIC_MAPPING = winnt::GENERIC_MAPPING {
	GenericRead: winnt::FILE_GENERIC_READ,
	GenericWrite: winnt::FILE_GENERIC_WRITE,
	GenericExecute: winnt::FILE_GENERIC_EXECUTE,
	GenericAll: winnt::FILE_ALL_ACCESS,
};

impl SecurityDescriptor {
	pub fn new_inherited(
		parent_desc: &SecurityDescriptor,
		creator_desc: winnt::PSECURITY_DESCRIPTOR,
		token: ntdef::HANDLE,
		is_dir: bool,
	) -> OperationResult<Self> {
		unsafe {
			if !creator_desc.is_null()
				&& securitybaseapi::IsValidSecurityDescriptor(creator_desc) == minwindef::FALSE
			{
				return Err(STATUS_INVALID_PARAMETER);
			}

			let mut priv_desc = ptr::null_mut();
			win32_ensure(
				securitybaseapi::CreatePrivateObjectSecurity(
					parent_desc.desc_ptr,
					creator_desc,
					&raw mut priv_desc,
					minwindef::BOOL::from(is_dir),
					token,
					std::ptr::from_ref(&FILE_GENERIC_MAPPING).cast_mut(),
				) == minwindef::TRUE,
			)?;

			let priv_desc = PrivateObjectSecurity::from_raw(priv_desc);

			let heap = heapapi::GetProcessHeap();
			win32_ensure(!heap.is_null())?;

			let len = securitybaseapi::GetSecurityDescriptorLength(priv_desc.value) as usize;
			let buf = heapapi::HeapAlloc(heap, 0, len);
			win32_ensure(!buf.is_null())?;

			ptr::copy_nonoverlapping(priv_desc.value as *const u8, buf.cast(), len);
			Ok(Self { desc_ptr: buf })
		}
	}

	pub fn new_default() -> OperationResult<Self> {
		let mut owner_sid = get_well_known_sid(winnt::WinLocalSystemSid)?;
		let mut group_sid = get_well_known_sid(winnt::WinLocalSystemSid)?;
		let mut dacl = create_default_dacl()?;

		unsafe {
			let mut abs_desc = mem::zeroed::<winnt::SECURITY_DESCRIPTOR>();
			let abs_desc_ptr = &raw mut abs_desc as winnt::PSECURITY_DESCRIPTOR;

			win32_ensure(
				securitybaseapi::InitializeSecurityDescriptor(
					abs_desc_ptr,
					winnt::SECURITY_DESCRIPTOR_REVISION,
				) == minwindef::TRUE,
			)?;

			win32_ensure(
				securitybaseapi::SetSecurityDescriptorOwner(
					abs_desc_ptr,
					owner_sid.as_mut_sid(),
					minwindef::FALSE,
				) == minwindef::TRUE,
			)?;

			win32_ensure(
				securitybaseapi::SetSecurityDescriptorGroup(
					abs_desc_ptr,
					group_sid.as_mut_sid(),
					minwindef::FALSE,
				) == minwindef::TRUE,
			)?;

			win32_ensure(
				securitybaseapi::SetSecurityDescriptorDacl(
					abs_desc_ptr,
					minwindef::TRUE,
					dacl.as_mut_acl(),
					minwindef::FALSE,
				) == minwindef::TRUE,
			)?;

			let mut len = 0;
			let ret =
				securitybaseapi::MakeSelfRelativeSD(abs_desc_ptr, ptr::null_mut(), &raw mut len);
			let err = GetLastError();
			if ret != minwindef::FALSE || err != winerror::ERROR_INSUFFICIENT_BUFFER {
				return Err(map_win32_error_to_ntstatus(err));
			}

			let heap = heapapi::GetProcessHeap();
			win32_ensure(!heap.is_null())?;

			let buf = heapapi::HeapAlloc(heap, 0, len as usize);
			win32_ensure(!buf.is_null())?;

			if securitybaseapi::MakeSelfRelativeSD(abs_desc_ptr, buf, &raw mut len)
				!= minwindef::TRUE
			{
				let error = GetLastError();
				heapapi::HeapFree(heap, 0, buf);
				return Err(map_win32_error_to_ntstatus(error));
			}

			Ok(Self { desc_ptr: buf })
		}
	}

	pub fn get_security_info(
		&self,
		sec_info: winnt::SECURITY_INFORMATION,
		sec_desc: winnt::PSECURITY_DESCRIPTOR,
		sec_desc_len: u32,
	) -> OperationResult<u32> {
		unsafe {
			let len = securitybaseapi::GetSecurityDescriptorLength(self.desc_ptr);
			if len > sec_desc_len {
				return Ok(len);
			}

			let mut ret_len = 0;
			win32_ensure(
				securitybaseapi::GetPrivateObjectSecurity(
					self.desc_ptr,
					sec_info,
					sec_desc,
					sec_desc_len,
					&raw mut ret_len,
				) == minwindef::TRUE,
			)?;

			Ok(len)
		}
	}

	pub fn set_security_info(
		&mut self,
		sec_info: winnt::SECURITY_INFORMATION,
		sec_desc: winnt::PSECURITY_DESCRIPTOR,
	) -> OperationResult<()> {
		unsafe {
			if securitybaseapi::IsValidSecurityDescriptor(sec_desc) == minwindef::FALSE {
				return Err(STATUS_INVALID_PARAMETER);
			}

			win32_ensure(
				securitybaseapi::SetPrivateObjectSecurityEx(
					sec_info,
					sec_desc,
					&raw mut self.desc_ptr,
					winnt::SEF_AVOID_PRIVILEGE_CHECK | winnt::SEF_AVOID_OWNER_CHECK,
					std::ptr::from_ref(&FILE_GENERIC_MAPPING).cast_mut(),
					ptr::null_mut(),
				) == minwindef::TRUE,
			)?;

			Ok(())
		}
	}
}

impl Drop for SecurityDescriptor {
	fn drop(&mut self) {
		unsafe {
			heapapi::HeapFree(heapapi::GetProcessHeap(), 0, self.desc_ptr);
		}
	}
}
