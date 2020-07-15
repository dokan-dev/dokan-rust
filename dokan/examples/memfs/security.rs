use std::{mem, ptr, slice};
use std::pin::Pin;

use dokan::OperationError;
use winapi::shared::{minwindef, ntdef, ntstatus::*, winerror};
use winapi::um::{errhandlingapi, securitybaseapi, winnt};

use crate::err_utils::*;

#[derive(Debug)]
struct PrivateObjectSecurity {
	value: winnt::PSECURITY_DESCRIPTOR,
}

impl PrivateObjectSecurity {
	unsafe fn from_raw(ptr: winnt::PSECURITY_DESCRIPTOR) -> Self {
		Self {
			value: ptr,
		}
	}
}

impl Drop for PrivateObjectSecurity {
	fn drop(&mut self) {
		unsafe {
			securitybaseapi::DestroyPrivateObjectSecurity(&mut self.value);
		}
	}
}

#[derive(Debug)]
pub struct SecurityDescriptor {
	owner_sid: Pin<Box<[u8]>>,
	group_sid: Pin<Box<[u8]>>,
	dacl: Pin<Box<[u8]>>,
	sacl: Pin<Box<[u8]>>,
	abs_desc: Box<[u8]>,
}

fn get_well_known_sid(sid_type: winnt::WELL_KNOWN_SID_TYPE) -> Result<Box<[u8]>, OperationError> {
	unsafe {
		let mut sid = vec![0u8; mem::size_of::<winnt::SID>() + mem::size_of::<u32>() * 7].into_boxed_slice();
		let mut len = sid.len() as u32;
		let ret = securitybaseapi::CreateWellKnownSid(
			sid_type,
			ptr::null_mut(),
			sid.as_mut_ptr() as winnt::PSID,
			&mut len,
		);
		if ret == minwindef::TRUE { Ok(sid) } else { win32_last_res() }
	}
}

fn duplicate_sid(sid: winnt::PSID) -> Result<Box<[u8]>, OperationError> {
	unsafe {
		if securitybaseapi::IsValidSid(sid) == minwindef::FALSE {
			return nt_res(STATUS_INVALID_PARAMETER);
		}
		let sid_len = securitybaseapi::GetLengthSid(sid);
		let mut buf = vec![0u8; sid_len as usize].into_boxed_slice();
		let ret = securitybaseapi::CopySid(sid_len, buf.as_mut_ptr() as winnt::PSID, sid);
		if ret == minwindef::TRUE { Ok(buf) } else { win32_last_res() }
	}
}

fn duplicate_acl(acl: winnt::PACL) -> Result<Box<[u8]>, OperationError> {
	unsafe {
		if securitybaseapi::IsValidAcl(acl) == minwindef::FALSE {
			return nt_res(STATUS_INVALID_PARAMETER);
		}
		let mut size_info = mem::zeroed::<winnt::ACL_SIZE_INFORMATION>();
		let ret = securitybaseapi::GetAclInformation(
			acl,
			&mut size_info as winnt::PACL_SIZE_INFORMATION as minwindef::LPVOID,
			mem::size_of_val(&size_info) as u32,
			winnt::AclSizeInformation,
		);
		if ret == minwindef::FALSE {
			return win32_last_res();
		}
		let len = (size_info.AclBytesInUse + size_info.AclBytesFree) as usize;
		let mut buf = vec![0u8; len].into_boxed_slice();
		buf.copy_from_slice(slice::from_raw_parts(acl as *mut _, len));
		Ok(buf)
	}
}

fn create_default_dacl() -> Result<Box<[u8]>, OperationError> {
	unsafe {
		let admins_sid = get_well_known_sid(winnt::WinBuiltinAdministratorsSid)?;
		let system_sid = get_well_known_sid(winnt::WinLocalSystemSid)?;
		let auth_sid = get_well_known_sid(winnt::WinAuthenticatedUserSid)?;
		let users_sid = get_well_known_sid(winnt::WinBuiltinUsersSid)?;

		let acl_len = mem::size_of::<winnt::ACL>()
			+ (mem::size_of::<winnt::ACCESS_ALLOWED_ACE>() - mem::size_of::<u32>()) * 4
			+ admins_sid.len() + system_sid.len() + auth_sid.len() + users_sid.len();
		let mut acl = vec![0u8; acl_len].into_boxed_slice();
		let ret = securitybaseapi::InitializeAcl(
			acl.as_mut_ptr() as winnt::PACL, acl_len as u32,
			winnt::ACL_REVISION as u32,
		);
		if ret == minwindef::FALSE {
			return win32_last_res();
		}

		let flags = (winnt::CONTAINER_INHERIT_ACE | winnt::OBJECT_INHERIT_ACE) as u32;
		let ret = securitybaseapi::AddAccessAllowedAceEx(
			acl.as_mut_ptr() as winnt::PACL,
			winnt::ACL_REVISION as u32,
			flags,
			winnt::FILE_ALL_ACCESS,
			admins_sid.as_ptr() as winnt::PSID,
		);
		if ret == minwindef::FALSE {
			return win32_last_res();
		}
		let ret = securitybaseapi::AddAccessAllowedAceEx(
			acl.as_mut_ptr() as winnt::PACL,
			winnt::ACL_REVISION as u32,
			flags,
			winnt::FILE_ALL_ACCESS,
			system_sid.as_ptr() as winnt::PSID,
		);
		if ret == minwindef::FALSE {
			return win32_last_res();
		}
		let ret = securitybaseapi::AddAccessAllowedAceEx(
			acl.as_mut_ptr() as winnt::PACL,
			winnt::ACL_REVISION as u32,
			flags,
			winnt::FILE_GENERIC_READ | winnt::FILE_GENERIC_WRITE | winnt::FILE_GENERIC_EXECUTE | winnt::DELETE,
			auth_sid.as_ptr() as winnt::PSID,
		);
		if ret == minwindef::FALSE {
			return win32_last_res();
		}
		let ret = securitybaseapi::AddAccessAllowedAceEx(
			acl.as_mut_ptr() as winnt::PACL,
			winnt::ACL_REVISION as u32,
			flags,
			winnt::FILE_GENERIC_READ | winnt::FILE_GENERIC_EXECUTE,
			users_sid.as_ptr() as winnt::PSID,
		);
		if ret == minwindef::FALSE {
			return win32_last_res();
		}

		Ok(acl)
	}
}

fn sd_get_control(desc: winnt::PSECURITY_DESCRIPTOR) -> Result<winnt::SECURITY_DESCRIPTOR_CONTROL, OperationError> {
	unsafe {
		let mut ctrl = 0;
		let mut rev = 0;
		let ret = securitybaseapi::GetSecurityDescriptorControl(desc, &mut ctrl, &mut rev);
		if ret == minwindef::TRUE { Ok(ctrl) } else { win32_last_res() }
	}
}

impl SecurityDescriptor {
	fn new() -> Result<Self, OperationError> {
		unsafe {
			let mut abs_desc = vec![0u8; mem::size_of::<winnt::SECURITY_DESCRIPTOR>()].into_boxed_slice();
			let ret = securitybaseapi::InitializeSecurityDescriptor(
				abs_desc.as_mut_ptr() as winnt::PSECURITY_DESCRIPTOR,
				winnt::SECURITY_DESCRIPTOR_REVISION,
			);
			if ret == minwindef::TRUE {
				Ok(Self {
					owner_sid: Pin::new(Vec::new().into_boxed_slice()),
					group_sid: Pin::new(Vec::new().into_boxed_slice()),
					dacl: Pin::new(Vec::new().into_boxed_slice()),
					sacl: Pin::new(Vec::new().into_boxed_slice()),
					abs_desc,
				})
			} else {
				win32_last_res()
			}
		}
	}

	pub fn new_inherited(
		parent_desc: &SecurityDescriptor,
		creator_desc: winnt::PSECURITY_DESCRIPTOR,
		token: ntdef::HANDLE,
		is_dir: bool,
	) -> Result<Self, OperationError> {
		unsafe {
			let mut mapping = winnt::GENERIC_MAPPING {
				GenericRead: winnt::FILE_GENERIC_READ,
				GenericWrite: winnt::FILE_GENERIC_WRITE,
				GenericExecute: winnt::FILE_GENERIC_EXECUTE,
				GenericAll: winnt::FILE_ALL_ACCESS,
			};

			if !creator_desc.is_null() && securitybaseapi::IsValidSecurityDescriptor(creator_desc) == minwindef::FALSE {
				return nt_res(STATUS_INVALID_PARAMETER);
			}

			let mut priv_desc = ptr::null_mut();
			let ret = securitybaseapi::CreatePrivateObjectSecurity(
				parent_desc.desc_ptr(),
				creator_desc,
				&mut priv_desc,
				is_dir as minwindef::BOOL,
				token,
				&mut mapping,
			);
			if ret == minwindef::FALSE {
				return win32_last_res();
			}
			let priv_desc = PrivateObjectSecurity::from_raw(priv_desc);

			let mut abs_desc_len = 0;
			let mut owner_len = 0;
			let mut group_len = 0;
			let mut dacl_len = 0;
			let mut sacl_len = 0;
			let ret = securitybaseapi::MakeAbsoluteSD(
				priv_desc.value,
				ptr::null_mut(), &mut abs_desc_len,
				ptr::null_mut(), &mut dacl_len,
				ptr::null_mut(), &mut sacl_len,
				ptr::null_mut(), &mut owner_len,
				ptr::null_mut(), &mut group_len,
			);
			let err = errhandlingapi::GetLastError();
			if ret != minwindef::FALSE || err != winerror::ERROR_INSUFFICIENT_BUFFER {
				return Err(OperationError::Win32(err));
			}

			let mut desc = Self {
				owner_sid: Pin::new(vec![0; owner_len as usize].into_boxed_slice()),
				group_sid: Pin::new(vec![0; group_len as usize].into_boxed_slice()),
				dacl: Pin::new(vec![0; dacl_len as usize].into_boxed_slice()),
				sacl: Pin::new(vec![0; sacl_len as usize].into_boxed_slice()),
				abs_desc: vec![0; abs_desc_len as usize].into_boxed_slice(),
			};
			let ret = securitybaseapi::MakeAbsoluteSD(
				priv_desc.value,
				desc.desc_mut_ptr(), &mut abs_desc_len,
				desc.dacl.as_mut_ptr() as winnt::PACL, &mut dacl_len,
				desc.sacl.as_mut_ptr() as winnt::PACL, &mut sacl_len,
				desc.owner_sid.as_mut_ptr() as winnt::PSID, &mut owner_len,
				desc.group_sid.as_mut_ptr() as winnt::PSID, &mut group_len,
			);
			if ret == minwindef::TRUE { Ok(desc) } else { win32_last_res() }
		}
	}

	fn desc_ptr(&self) -> winnt::PSECURITY_DESCRIPTOR {
		self.abs_desc.as_ptr() as winnt::PSECURITY_DESCRIPTOR
	}

	fn desc_mut_ptr(&mut self) -> winnt::PSECURITY_DESCRIPTOR {
		self.abs_desc.as_mut_ptr() as winnt::PSECURITY_DESCRIPTOR
	}

	fn set_owner(&mut self, owner: winnt::PSID, defaulted: minwindef::BOOL) -> Result<(), OperationError> {
		unsafe {
			let new_sid = Pin::new(duplicate_sid(owner)?);
			let ret = securitybaseapi::SetSecurityDescriptorOwner(
				self.desc_mut_ptr(),
				new_sid.as_ptr() as winnt::PSID, defaulted,
			);
			if ret == minwindef::FALSE {
				return win32_last_res();
			}
			self.owner_sid = new_sid;
			Ok(())
		}
	}

	fn set_group(&mut self, group: winnt::PSID, defaulted: minwindef::BOOL) -> Result<(), OperationError> {
		unsafe {
			let new_sid = Pin::new(duplicate_sid(group)?);
			let ret = securitybaseapi::SetSecurityDescriptorGroup(
				self.desc_mut_ptr(),
				new_sid.as_ptr() as winnt::PSID, defaulted,
			);
			if ret == minwindef::FALSE {
				return win32_last_res();
			}
			self.group_sid = new_sid;
			Ok(())
		}
	}

	fn set_dacl(&mut self, dacl: winnt::PACL, defaulted: minwindef::BOOL) -> Result<(), OperationError> {
		unsafe {
			let new_dacl = Pin::new(duplicate_acl(dacl)?);
			let ret = securitybaseapi::SetSecurityDescriptorDacl(
				self.desc_mut_ptr(),
				minwindef::TRUE, new_dacl.as_ptr() as winnt::PACL, defaulted,
			);
			if ret == minwindef::FALSE {
				return win32_last_res();
			}
			self.dacl = new_dacl;
			Ok(())
		}
	}

	fn remove_dacl(&mut self) -> Result<(), OperationError> {
		unsafe {
			let ret = securitybaseapi::SetSecurityDescriptorDacl(
				self.desc_mut_ptr(),
				minwindef::FALSE, ptr::null_mut(), minwindef::FALSE,
			);
			if ret == minwindef::TRUE { Ok(()) } else { win32_last_res() }
		}
	}

	fn set_sacl(&mut self, sacl: winnt::PACL, defaulted: minwindef::BOOL) -> Result<(), OperationError> {
		unsafe {
			let new_sacl = Pin::new(duplicate_acl(sacl)?);
			let ret = securitybaseapi::SetSecurityDescriptorSacl(
				self.desc_mut_ptr(),
				minwindef::TRUE, new_sacl.as_ptr() as winnt::PACL, defaulted,
			);
			if ret == minwindef::FALSE {
				panic!("SetSecurityDescriptorSacl failed: {}", errhandlingapi::GetLastError());
			}
			self.sacl = new_sacl;
			Ok(())
		}
	}

	fn remove_sacl(&mut self) -> Result<(), OperationError> {
		unsafe {
			let ret = securitybaseapi::SetSecurityDescriptorSacl(
				self.desc_mut_ptr(),
				minwindef::FALSE, ptr::null_mut(), minwindef::FALSE,
			);
			if ret == minwindef::TRUE { Ok(()) } else { win32_last_res() }
		}
	}

	fn set_control(&mut self, ctrl: winnt::SECURITY_DESCRIPTOR_CONTROL) -> Result<(), OperationError> {
		unsafe {
			const MASK: winnt::SECURITY_DESCRIPTOR_CONTROL = winnt::SE_DACL_AUTO_INHERITED | winnt::SE_DACL_AUTO_INHERIT_REQ
				| winnt::SE_DACL_PROTECTED | winnt::SE_SACL_AUTO_INHERITED | winnt::SE_SACL_AUTO_INHERIT_REQ
				| winnt::SE_SACL_PROTECTED;
			let ret = securitybaseapi::SetSecurityDescriptorControl(
				self.desc_mut_ptr(),
				MASK, ctrl & MASK,
			);
			if ret == minwindef::TRUE { Ok(()) } else { win32_last_res() }
		}
	}

	pub fn new_default() -> Result<Self, OperationError> {
		let owner_sid = Pin::new(get_well_known_sid(winnt::WinLocalSystemSid)?);
		let group_sid = Pin::new(get_well_known_sid(winnt::WinLocalSystemSid)?);
		let dacl = Pin::new(create_default_dacl()?);

		let mut desc = Self::new()?;
		desc.set_control(winnt::SE_DACL_AUTO_INHERITED | winnt::SE_DACL_AUTO_INHERITED)?;
		desc.set_owner(owner_sid.as_ptr() as winnt::PSID, minwindef::FALSE)?;
		desc.set_group(group_sid.as_ptr() as winnt::PSID, minwindef::FALSE)?;
		desc.set_dacl(dacl.as_ptr() as winnt::PACL, minwindef::FALSE)?;
		Ok(desc)
	}

	pub fn get_security_info(
		&self,
		sec_info: winnt::SECURITY_INFORMATION,
		sec_desc: winnt::PSECURITY_DESCRIPTOR,
		mut sec_desc_len: u32,
	) -> Result<u32, OperationError> {
		let mut tmp_desc = SecurityDescriptor::new()?;
		let ctrl = sd_get_control(self.desc_ptr())?;
		tmp_desc.set_control(ctrl)?;

		if sec_info & winnt::OWNER_SECURITY_INFORMATION > 0 {
			tmp_desc.set_owner(
				self.owner_sid.as_ptr() as winnt::PSID,
				(ctrl & winnt::SE_OWNER_DEFAULTED > 0) as minwindef::BOOL,
			)?;
		}

		if sec_info & winnt::GROUP_SECURITY_INFORMATION > 0 {
			tmp_desc.set_group(
				self.group_sid.as_ptr() as winnt::PSID,
				(ctrl & winnt::SE_GROUP_DEFAULTED > 0) as minwindef::BOOL,
			)?;
		}

		if sec_info & winnt::DACL_SECURITY_INFORMATION > 0 && ctrl & winnt::SE_DACL_PRESENT > 0 {
			tmp_desc.set_dacl(
				self.dacl.as_ptr() as winnt::PACL,
				(ctrl & winnt::SE_DACL_DEFAULTED > 0) as minwindef::BOOL,
			)?;
		}

		if sec_info & winnt::SACL_SECURITY_INFORMATION > 0 && ctrl & winnt::SE_SACL_PRESENT > 0 {
			tmp_desc.set_sacl(
				self.sacl.as_ptr() as winnt::PACL,
				(ctrl & winnt::SE_SACL_DEFAULTED > 0) as minwindef::BOOL,
			)?;
		}

		unsafe {
			let ret = securitybaseapi::MakeSelfRelativeSD(tmp_desc.desc_ptr(), sec_desc, &mut sec_desc_len);
			let err = errhandlingapi::GetLastError();
			if ret == minwindef::TRUE || err == winerror::ERROR_INSUFFICIENT_BUFFER {
				Ok(sec_desc_len)
			} else {
				Err(OperationError::Win32(err))
			}
		}
	}

	pub fn set_security_info(
		&mut self,
		sec_info: winnt::SECURITY_INFORMATION,
		sec_desc: winnt::PSECURITY_DESCRIPTOR,
	) -> Result<(), OperationError> {
		unsafe {
			if securitybaseapi::IsValidSecurityDescriptor(sec_desc) == minwindef::FALSE {
				return nt_res(STATUS_INVALID_PARAMETER);
			}

			let ctrl = sd_get_control(sec_desc)?;
			self.set_control(ctrl)?;

			if sec_info & winnt::OWNER_SECURITY_INFORMATION > 0 {
				let mut owner_sid = ptr::null_mut();
				let mut owner_defaulted = 0;
				let ret = securitybaseapi::GetSecurityDescriptorOwner(
					sec_desc, &mut owner_sid, &mut owner_defaulted,
				);
				if ret == minwindef::FALSE {
					return win32_last_res();
				}
				self.set_owner(owner_sid, owner_defaulted)?;
			}

			if sec_info & winnt::GROUP_SECURITY_INFORMATION > 0 {
				let mut group_sid = ptr::null_mut();
				let mut group_defaulted = 0;
				let ret = securitybaseapi::GetSecurityDescriptorGroup(
					sec_desc, &mut group_sid, &mut group_defaulted,
				);
				if ret == minwindef::FALSE {
					return win32_last_res();
				}
				self.set_group(group_sid, group_defaulted)?;
			}

			if sec_info & winnt::DACL_SECURITY_INFORMATION > 0 {
				let mut dacl_present = 0;
				let mut dacl = ptr::null_mut();
				let mut dacl_defaulted = 0;
				let ret = securitybaseapi::GetSecurityDescriptorDacl(
					sec_desc, &mut dacl_present, &mut dacl, &mut dacl_defaulted,
				);
				if ret == minwindef::FALSE {
					return win32_last_res();
				}
				if dacl_present == minwindef::TRUE {
					self.set_dacl(dacl, dacl_defaulted)?;
				} else {
					self.remove_dacl()?;
				}
			}

			if sec_info & winnt::SACL_SECURITY_INFORMATION > 0 {
				let mut sacl_present = 0;
				let mut sacl = ptr::null_mut();
				let mut sacl_defaulted = 0;
				let ret = securitybaseapi::GetSecurityDescriptorSacl(
					sec_desc, &mut sacl_present, &mut sacl, &mut sacl_defaulted,
				);
				if ret == minwindef::FALSE {
					return win32_last_res();
				}
				if sacl_present == minwindef::TRUE {
					self.set_sacl(sacl, sacl_defaulted)?;
				} else {
					self.remove_sacl()?;
				}
			}
		}
		Ok(())
	}
}
