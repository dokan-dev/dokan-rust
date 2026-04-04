use std::{mem, pin::Pin, ptr};

use dokan::{OperationResult, map_win32_error_to_ntstatus, win32_ensure};
use windows_sys::Win32::{
	Foundation::{
		ERROR_INSUFFICIENT_BUFFER, FALSE, GetLastError, HANDLE, STATUS_INVALID_PARAMETER, TRUE,
	},
	Security::{
		ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAceEx, CONTAINER_INHERIT_ACE,
		CreatePrivateObjectSecurity, CreateWellKnownSid, DestroyPrivateObjectSecurity,
		GENERIC_MAPPING, GetPrivateObjectSecurity, GetSecurityDescriptorLength, InitializeAcl,
		InitializeSecurityDescriptor, IsValidSecurityDescriptor, MakeSelfRelativeSD,
		OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID, SECURITY_DESCRIPTOR, SEF_AVOID_OWNER_CHECK,
		SEF_AVOID_PRIVILEGE_CHECK, SID, SetPrivateObjectSecurityEx, SetSecurityDescriptorDacl,
		SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, WELL_KNOWN_SID_TYPE,
		WinAuthenticatedUserSid, WinBuiltinAdministratorsSid, WinBuiltinUsersSid,
		WinLocalSystemSid,
	},
	Storage::FileSystem::{
		DELETE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
	},
	System::{
		Memory::{GetProcessHeap, HeapAlloc, HeapFree},
		SystemServices::SECURITY_DESCRIPTOR_REVISION,
	},
};

type PACL = *mut ACL;

#[derive(Debug)]
struct PrivateObjectSecurity {
	value: PSECURITY_DESCRIPTOR,
}

impl PrivateObjectSecurity {
	unsafe fn from_raw(ptr: PSECURITY_DESCRIPTOR) -> Self {
		Self { value: ptr }
	}
}

impl Drop for PrivateObjectSecurity {
	fn drop(&mut self) {
		unsafe {
			DestroyPrivateObjectSecurity(&mut self.value);
		}
	}
}

#[derive(Debug)]
pub struct SecurityDescriptor {
	desc_ptr: PSECURITY_DESCRIPTOR,
}

unsafe impl Sync for SecurityDescriptor {}

unsafe impl Send for SecurityDescriptor {}

fn get_well_known_sid(sid_type: WELL_KNOWN_SID_TYPE) -> OperationResult<Box<[u8]>> {
	unsafe {
		let mut sid =
			vec![0u8; mem::size_of::<SID>() + mem::size_of::<u32>() * 7].into_boxed_slice();
		let mut len = sid.len() as u32;
		win32_ensure(
			CreateWellKnownSid(
				sid_type,
				ptr::null_mut(),
				sid.as_mut_ptr() as PSID,
				&mut len,
			) == TRUE,
		)?;
		Ok(sid)
	}
}

fn create_default_dacl() -> OperationResult<Box<[u8]>> {
	unsafe {
		let admins_sid = get_well_known_sid(WinBuiltinAdministratorsSid)?;
		let system_sid = get_well_known_sid(WinLocalSystemSid)?;
		let auth_sid = get_well_known_sid(WinAuthenticatedUserSid)?;
		let users_sid = get_well_known_sid(WinBuiltinUsersSid)?;

		let acl_len = mem::size_of::<ACL>()
			+ (mem::size_of::<ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>()) * 4
			+ admins_sid.len()
			+ system_sid.len()
			+ auth_sid.len()
			+ users_sid.len();
		let mut acl = vec![0u8; acl_len].into_boxed_slice();
		win32_ensure(
			InitializeAcl(
				acl.as_mut_ptr() as PACL,
				acl_len as u32,
				ACL_REVISION as u32,
			) == TRUE,
		)?;

		let flags = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) as u32;
		win32_ensure(
			AddAccessAllowedAceEx(
				acl.as_mut_ptr() as PACL,
				ACL_REVISION as u32,
				flags,
				FILE_ALL_ACCESS,
				admins_sid.as_ptr() as PSID,
			) == TRUE,
		)?;

		win32_ensure(
			AddAccessAllowedAceEx(
				acl.as_mut_ptr() as PACL,
				ACL_REVISION as u32,
				flags,
				FILE_ALL_ACCESS,
				system_sid.as_ptr() as PSID,
			) == TRUE,
		)?;

		win32_ensure(
			AddAccessAllowedAceEx(
				acl.as_mut_ptr() as PACL,
				ACL_REVISION as u32,
				flags,
				FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE,
				auth_sid.as_ptr() as PSID,
			) == TRUE,
		)?;

		win32_ensure(
			AddAccessAllowedAceEx(
				acl.as_mut_ptr() as PACL,
				ACL_REVISION as u32,
				flags,
				FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
				users_sid.as_ptr() as PSID,
			) == TRUE,
		)?;

		Ok(acl)
	}
}

const FILE_GENERIC_MAPPING: GENERIC_MAPPING = GENERIC_MAPPING {
	GenericRead: FILE_GENERIC_READ,
	GenericWrite: FILE_GENERIC_WRITE,
	GenericExecute: FILE_GENERIC_EXECUTE,
	GenericAll: FILE_ALL_ACCESS,
};

impl SecurityDescriptor {
	pub fn new_inherited(
		parent_desc: &SecurityDescriptor,
		creator_desc: PSECURITY_DESCRIPTOR,
		token: HANDLE,
		is_dir: bool,
	) -> OperationResult<Self> {
		unsafe {
			if !creator_desc.is_null() && IsValidSecurityDescriptor(creator_desc) == FALSE {
				return Err(STATUS_INVALID_PARAMETER);
			}

			let mut priv_desc = ptr::null_mut();
			win32_ensure(
				CreatePrivateObjectSecurity(
					parent_desc.desc_ptr,
					creator_desc,
					&mut priv_desc,
					is_dir as i32,
					token,
					&FILE_GENERIC_MAPPING as *const _ as *mut _,
				) == TRUE,
			)?;

			let priv_desc = PrivateObjectSecurity::from_raw(priv_desc);

			let heap = GetProcessHeap();
			win32_ensure(!heap.is_null())?;

			let len = GetSecurityDescriptorLength(priv_desc.value) as usize;
			let buf = HeapAlloc(heap, 0, len);
			win32_ensure(!buf.is_null())?;

			ptr::copy_nonoverlapping(priv_desc.value as *const u8, buf as *mut _, len);
			Ok(Self { desc_ptr: buf })
		}
	}

	pub fn new_default() -> OperationResult<Self> {
		let owner_sid = Pin::new(get_well_known_sid(WinLocalSystemSid)?);
		let group_sid = Pin::new(get_well_known_sid(WinLocalSystemSid)?);
		let dacl = Pin::new(create_default_dacl()?);

		unsafe {
			let mut abs_desc = mem::zeroed::<SECURITY_DESCRIPTOR>();
			let abs_desc_ptr = &mut abs_desc as *mut _ as PSECURITY_DESCRIPTOR;

			win32_ensure(
				InitializeSecurityDescriptor(abs_desc_ptr, SECURITY_DESCRIPTOR_REVISION) == TRUE,
			)?;

			win32_ensure(
				SetSecurityDescriptorOwner(abs_desc_ptr, owner_sid.as_ptr() as PSID, FALSE) == TRUE,
			)?;

			win32_ensure(
				SetSecurityDescriptorGroup(abs_desc_ptr, group_sid.as_ptr() as PSID, FALSE) == TRUE,
			)?;

			win32_ensure(
				SetSecurityDescriptorDacl(abs_desc_ptr, TRUE, dacl.as_ptr() as PACL, FALSE) == TRUE,
			)?;

			let mut len = 0;
			let ret = MakeSelfRelativeSD(abs_desc_ptr, ptr::null_mut(), &mut len);
			let err = GetLastError();
			if ret != FALSE || err != ERROR_INSUFFICIENT_BUFFER {
				return Err(map_win32_error_to_ntstatus(err));
			}

			let heap = GetProcessHeap();
			win32_ensure(!heap.is_null())?;

			let buf = HeapAlloc(heap, 0, len as usize);
			win32_ensure(!buf.is_null())?;

			win32_ensure(MakeSelfRelativeSD(abs_desc_ptr, buf, &mut len) == TRUE)?;

			Ok(Self { desc_ptr: buf })
		}
	}

	pub fn get_security_info(
		&self,
		sec_info: u32,
		sec_desc: PSECURITY_DESCRIPTOR,
		sec_desc_len: u32,
	) -> OperationResult<u32> {
		unsafe {
			let len = GetSecurityDescriptorLength(self.desc_ptr);
			if len > sec_desc_len {
				return Ok(len);
			}

			let mut ret_len = 0;
			win32_ensure(
				GetPrivateObjectSecurity(
					self.desc_ptr,
					sec_info,
					sec_desc,
					sec_desc_len,
					&mut ret_len,
				) == TRUE,
			)?;

			Ok(len)
		}
	}

	pub fn set_security_info(
		&mut self,
		sec_info: u32,
		sec_desc: PSECURITY_DESCRIPTOR,
	) -> OperationResult<()> {
		unsafe {
			if IsValidSecurityDescriptor(sec_desc) == FALSE {
				return Err(STATUS_INVALID_PARAMETER);
			}

			win32_ensure(
				SetPrivateObjectSecurityEx(
					sec_info,
					sec_desc,
					&mut self.desc_ptr,
					SEF_AVOID_PRIVILEGE_CHECK | SEF_AVOID_OWNER_CHECK,
					&FILE_GENERIC_MAPPING as *const _ as *mut _,
					ptr::null_mut(),
				) == TRUE,
			)?;

			Ok(())
		}
	}
}

impl Drop for SecurityDescriptor {
	fn drop(&mut self) {
		unsafe {
			HeapFree(GetProcessHeap(), 0, self.desc_ptr);
		}
	}
}
