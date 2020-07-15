extern crate dokan;
extern crate widestring;
extern crate winapi;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::hash_map;
use std::hash::{Hash, Hasher};
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, RwLock, Weak};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use dokan::*;
use widestring::{U16CStr, U16Str, U16CString, U16String};
use winapi::shared::ntstatus::*;
use winapi::um::winnt;

mod security;
mod err_utils;

use security::*;
use err_utils::*;


#[derive(Debug)]
struct Stat {
	id: u64,
	attrs: u32,
	ctime: SystemTime,
	mtime: SystemTime,
	sec_desc: SecurityDescriptor,
	handle_count: u32,
	delete_pending: bool,
	parent: Weak<DirEntry>,
}

impl Stat {
	fn new(id: u64, attrs: u32, sec_desc: SecurityDescriptor, parent: Weak<DirEntry>) -> Self {
		let now = SystemTime::now();
		Self {
			id,
			attrs,
			ctime: now,
			mtime: now,
			sec_desc,
			handle_count: 0,
			delete_pending: false,
			parent,
		}
	}
}

#[derive(Debug, Eq)]
struct EntryNameRef(U16Str);

fn u16_tolower(c: u16) -> u16 {
	if c >= 'A' as u16 && c <= 'Z' as u16 {
		c + 'a' as u16 - 'A' as u16
	} else { c }
}

impl Hash for EntryNameRef {
	fn hash<H: Hasher>(&self, state: &mut H) {
		for c in self.0.as_slice() {
			state.write_u16(u16_tolower(*c));
		}
	}
}

impl PartialEq for EntryNameRef {
	fn eq(&self, other: &Self) -> bool {
		if self.0.len() != other.0.len() { false } else {
			self.0.as_slice().iter().zip(other.0.as_slice())
				.all(|(c1, c2)| u16_tolower(*c1) == u16_tolower(*c2))
		}
	}
}

impl EntryNameRef {
	fn new(s: &U16Str) -> &Self {
		unsafe { &*(s as *const _ as *const Self) }
	}
}

#[derive(Debug, Clone)]
struct EntryName(U16String);

impl Borrow<EntryNameRef> for EntryName {
	fn borrow(&self) -> &EntryNameRef {
		EntryNameRef::new(&self.0)
	}
}

impl Hash for EntryName {
	fn hash<H: Hasher>(&self, state: &mut H) {
		Borrow::<EntryNameRef>::borrow(self).hash(state)
	}
}

impl PartialEq for EntryName {
	fn eq(&self, other: &Self) -> bool {
		Borrow::<EntryNameRef>::borrow(self).eq(other.borrow())
	}
}

impl Eq for EntryName {}

fn canonicalize_attrs(mut attrs: u32, is_dir: bool) -> u32 {
	if is_dir {
		attrs |= winnt::FILE_ATTRIBUTE_DIRECTORY;
	} else {
		attrs &= !winnt::FILE_ATTRIBUTE_DIRECTORY;
	}
	if attrs == 0 {
		attrs = winnt::FILE_ATTRIBUTE_NORMAL
	} else if attrs != winnt::FILE_ATTRIBUTE_NORMAL {
		attrs &= !winnt::FILE_ATTRIBUTE_NORMAL
	}
	attrs
}

#[derive(Debug)]
struct FileEntry {
	stat: RwLock<Stat>,
	data: RwLock<Vec<u8>>,
}

impl FileEntry {
	fn new(mut stat: Stat) -> Self {
		stat.attrs = canonicalize_attrs(stat.attrs, false);
		Self {
			stat: RwLock::new(stat),
			data: RwLock::new(Vec::new()),
		}
	}
}

#[derive(Debug)]
struct DirEntry {
	stat: RwLock<Stat>,
	children: RwLock<HashMap<EntryName, Entry>>,
}

impl DirEntry {
	fn new(mut stat: Stat) -> Self {
		stat.attrs = canonicalize_attrs(stat.attrs, true);
		Self {
			stat: RwLock::new(stat),
			children: RwLock::new(HashMap::new()),
		}
	}
}

#[derive(Debug)]
enum Entry {
	File(Arc<FileEntry>),
	Directory(Arc<DirEntry>),
}

impl Entry {
	fn stat(&self) -> &RwLock<Stat> {
		match self {
			Entry::File(file) => &file.stat,
			Entry::Directory(dir) => &dir.stat,
		}
	}
}

impl PartialEq for Entry {
	fn eq(&self, other: &Self) -> bool {
		match self {
			Entry::File(file) => {
				if let Entry::File(other_file) = other {
					Arc::ptr_eq(file, other_file)
				} else {
					false
				}
			}
			Entry::Directory(dir) => {
				if let Entry::Directory(other_dir) = other {
					Arc::ptr_eq(dir, other_dir)
				} else {
					false
				}
			}
		}
	}
}

impl Eq for Entry {}

impl Clone for Entry {
	fn clone(&self) -> Self {
		match self {
			Entry::File(file) => Entry::File(Arc::clone(file)),
			Entry::Directory(dir) => Entry::Directory(Arc::clone(dir)),
		}
	}
}

#[derive(Debug)]
struct EntryHandle {
	entry: Entry,
	delete_on_close: bool,
}

impl EntryHandle {
	fn from_file(file: &Arc<FileEntry>, delete_on_close: bool) -> Self {
		file.stat.write().unwrap().handle_count += 1;
		Self {
			entry: Entry::File(file.clone()),
			delete_on_close,
		}
	}

	fn from_dir(dir: &Arc<DirEntry>, delete_on_close: bool) -> Self {
		dir.stat.write().unwrap().handle_count += 1;
		Self {
			entry: Entry::Directory(dir.clone()),
			delete_on_close,
		}
	}
}

impl Drop for EntryHandle {
	fn drop(&mut self) {
		// The read lock on stat will be released before locking parent. This avoids possible deadlocks with
		// create_file.
		let parent = self.entry.stat().read().unwrap().parent.upgrade();
		// Lock parent before checking. This avoids racing with create_file.
		let parent_children = parent.as_ref()
			.map(|p| p.children.write().unwrap());
		let mut stat = self.entry.stat().write().unwrap();
		if self.delete_on_close {
			stat.delete_pending = true;
		}
		stat.handle_count -= 1;
		if stat.delete_pending && stat.handle_count == 0 {
			// The result of upgrade() can be safely unwrapped here because the root directory is the only case when the
			// reference can be null, which has been handled in delete_directory.
			let mut parent_children = parent_children.unwrap();
			let key = parent_children.iter().find_map(|(k, v)| {
				if self.entry.eq(v) {
					Some(k)
				} else {
					None
				}
			}).unwrap().clone();
			parent_children.remove(Borrow::<EntryNameRef>::borrow(&key)).unwrap();
		}
	}
}

#[derive(Debug)]
struct MemFsHandler {
	id_counter: AtomicU64,
	root: Arc<DirEntry>,
}

impl MemFsHandler {
	fn new() -> Self {
		Self {
			id_counter: AtomicU64::new(1),
			root: Arc::new(DirEntry::new(Stat::new(
				0, 0,
				SecurityDescriptor::new_default().unwrap(),
				Weak::new(),
			))),
		}
	}

	fn find_dir_entry(cur_entry: &Arc<DirEntry>, path: &[&U16Str]) -> Option<Arc<DirEntry>> {
		if let Some(name) = path.get(0) {
			match cur_entry.children.read().unwrap().get(EntryNameRef::new(name)) {
				Some(Entry::Directory(dir)) => {
					Self::find_dir_entry(dir, &path[1..])
				}
				_ => None
			}
		} else {
			Some(Arc::clone(cur_entry))
		}
	}

	fn split_path<'a>(&self, path: &'a U16CStr) -> Result<Option<(&'a U16Str, Arc<DirEntry>)>, OperationError> {
		let path = path.as_slice()
			.split(|x| *x == '\\' as u16)
			.filter(|s| !s.is_empty())
			.map(|s| U16Str::from_slice(s))
			.collect::<Vec<_>>();
		if path.is_empty() { Ok(None) } else {
			Self::find_dir_entry(&self.root, &path[..path.len() - 1])
				.map(|x| Some((*path.iter().last().unwrap(), x)))
				.ok_or(nt_err(STATUS_OBJECT_NAME_NOT_FOUND))
		}
	}

	fn next_id(&self) -> u64 {
		self.id_counter.fetch_add(1, Ordering::Relaxed)
	}
}

const FILE_SUPERSEDE: u32 = 0;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_OPEN_IF: u32 = 3;
const FILE_OVERWRITE: u32 = 4;
const FILE_OVERWRITE_IF: u32 = 5;
const FILE_MAXIMUM_DISPOSITION: u32 = 5;

const FILE_DIRECTORY_FILE: u32 = 0x00000001;
const FILE_NON_DIRECTORY_FILE: u32 = 0x00000040;
const FILE_DELETE_ON_CLOSE: u32 = 0x00001000;

impl<'a, 'b: 'a> FileSystemHandler<'a, 'b> for MemFsHandler {
	type Context = EntryHandle;

	fn create_file(
		&'b self,
		file_name: &U16CStr,
		security_context: PDOKAN_IO_SECURITY_CONTEXT,
		_desired_access: winnt::ACCESS_MASK,
		file_attributes: u32,
		_share_access: u32,
		create_disposition: u32,
		create_options: u32,
		info: &mut OperationInfo<'a, 'b, Self>,
	) -> Result<CreateFileInfo<Self::Context>, OperationError> {
		if create_disposition > FILE_MAXIMUM_DISPOSITION {
			return nt_res(STATUS_INVALID_PARAMETER);
		}
		let creator_desc = unsafe { (&*security_context).AccessState.SecurityDescriptor };
		let delete_on_close = create_options & FILE_DELETE_ON_CLOSE > 0;
		let path_info = self.split_path(file_name)?;
		if let Some((name, parent)) = path_info {
			let mut children = parent.children.write().unwrap();
			match children.get(EntryNameRef::new(name)) {
				Some(Entry::File(file)) => {
					if create_options & FILE_DIRECTORY_FILE > 0 {
						return nt_res(STATUS_NOT_A_DIRECTORY);
					}
					let stat = file.stat.read().unwrap();
					if stat.attrs & winnt::FILE_ATTRIBUTE_READONLY > 0 || stat.delete_pending {
						return nt_res(STATUS_ACCESS_DENIED);
					}
					std::mem::drop(stat);
					match create_disposition {
						FILE_SUPERSEDE => {
							let token = info.requester_token().unwrap();
							let mut stat = file.stat.write().unwrap();
							let id = stat.id;
							*stat = Stat::new(
								id,
								canonicalize_attrs(file_attributes, false),
								SecurityDescriptor::new_inherited(
									&parent.stat.read().unwrap().sec_desc,
									creator_desc, token.as_raw_handle(), false,
								)?,
								Arc::downgrade(&parent),
							);
							file.data.write().unwrap().clear();
						}
						FILE_OVERWRITE | FILE_OVERWRITE_IF => file.data.write().unwrap().clear(),
						FILE_CREATE => return nt_res(STATUS_OBJECT_NAME_COLLISION),
						_ => (),
					}
					Ok(CreateFileInfo {
						context: EntryHandle::from_file(file, delete_on_close),
						is_dir: false,
						new_file_created: false,
					})
				}
				Some(Entry::Directory(dir)) => {
					if create_options & FILE_NON_DIRECTORY_FILE > 0 {
						return nt_res(STATUS_FILE_IS_A_DIRECTORY);
					}
					if dir.stat.read().unwrap().delete_pending {
						return nt_res(STATUS_ACCESS_DENIED);
					}
					match create_disposition {
						FILE_OPEN | FILE_OPEN_IF => {
							Ok(CreateFileInfo {
								context: EntryHandle::from_dir(dir, delete_on_close),
								is_dir: true,
								new_file_created: false,
							})
						}
						FILE_CREATE => nt_res(STATUS_OBJECT_NAME_COLLISION),
						_ => nt_res(STATUS_INVALID_PARAMETER),
					}
				}
				None => {
					if parent.stat.read().unwrap().delete_pending {
						return nt_res(STATUS_ACCESS_DENIED);
					}
					let token = info.requester_token().unwrap();
					if create_options & FILE_DIRECTORY_FILE > 0 {
						match create_disposition {
							FILE_CREATE | FILE_OPEN_IF => {
								let dir = Arc::new(DirEntry::new(Stat::new(
									self.next_id(),
									file_attributes,
									SecurityDescriptor::new_inherited(
										&parent.stat.read().unwrap().sec_desc,
										creator_desc, token.as_raw_handle(), true,
									)?,
									Arc::downgrade(&parent),
								)));
								assert_eq!(children.insert(
									EntryName(name.to_owned()),
									Entry::Directory(Arc::clone(&dir)),
								), None);
								parent.stat.write().unwrap().mtime = SystemTime::now();
								Ok(CreateFileInfo {
									context: EntryHandle::from_dir(&dir, delete_on_close),
									is_dir: true,
									new_file_created: true,
								})
							}
							FILE_OPEN => nt_res(STATUS_OBJECT_NAME_NOT_FOUND),
							_ => nt_res(STATUS_INVALID_PARAMETER),
						}
					} else {
						if create_disposition == FILE_OPEN || create_disposition == FILE_OVERWRITE {
							nt_res(STATUS_OBJECT_NAME_NOT_FOUND)
						} else {
							let file = Arc::new(FileEntry::new(Stat::new(
								self.next_id(),
								file_attributes,
								SecurityDescriptor::new_inherited(
									&parent.stat.read().unwrap().sec_desc,
									creator_desc, token.as_raw_handle(), false,
								)?,
								Arc::downgrade(&parent),
							)));
							assert_eq!(children.insert(
								EntryName(name.to_owned()),
								Entry::File(Arc::clone(&file)),
							), None);
							parent.stat.write().unwrap().mtime = SystemTime::now();
							Ok(CreateFileInfo {
								context: EntryHandle::from_file(&file, delete_on_close),
								is_dir: false,
								new_file_created: true,
							})
						}
					}
				}
			}
		} else {
			if create_disposition == FILE_OPEN || create_disposition == FILE_OPEN_IF {
				if create_options & FILE_NON_DIRECTORY_FILE > 0 {
					nt_res(STATUS_FILE_IS_A_DIRECTORY)
				} else {
					Ok(CreateFileInfo {
						context: EntryHandle::from_dir(&self.root, info.delete_on_close()),
						is_dir: true,
						new_file_created: false,
					})
				}
			} else {
				nt_res(STATUS_INVALID_PARAMETER)
			}
		}
	}

	fn read_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		buffer: &mut [u8],
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		if let Entry::File(file) = &context.entry {
			let data = file.data.read().unwrap();
			let offset = offset as usize;
			let len = std::cmp::min(buffer.len(), data.len() - offset);
			buffer[0..len].copy_from_slice(&data[offset..offset + len]);
			Ok(len as u32)
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		}
	}

	fn write_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		buffer: &[u8],
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		if let Entry::File(file) = &context.entry {
			let mut data = file.data.write().unwrap();
			let offset = if info.write_to_eof() { data.len() } else { offset as usize };
			let len = buffer.len();
			if offset + len > data.len() {
				data.resize(offset + len, 0);
			}
			data[offset..offset + len].copy_from_slice(buffer);
			Ok(len as u32)
		} else {
			nt_res(STATUS_ACCESS_DENIED)
		}
	}

	fn flush_file_buffers(
		&'b self,
		_file_name: &U16CStr,
		_info: &OperationInfo<'a, 'b, Self>,
		_context: &'a Self::Context,
	) -> Result<(), OperationError> {
		Ok(())
	}

	fn get_file_information(
		&'b self,
		_file_name: &U16CStr,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<FileInfo, OperationError> {
		let stat = context.entry.stat().read().unwrap();
		Ok(FileInfo {
			attributes: stat.attrs,
			creation_time: stat.ctime,
			last_access_time: stat.mtime,
			last_write_time: stat.mtime,
			file_size: match &context.entry {
				Entry::File(file) => {
					file.data.read().unwrap().len() as u64
				}
				Entry::Directory(_) => 0,
			},
			number_of_links: 1,
			file_index: stat.id,
		})
	}

	fn find_files(
		&'b self,
		_file_name: &U16CStr,
		mut fill_find_data: impl FnMut(&FindData) -> Result<(), FillDataError>,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		if let Entry::Directory(dir) = &context.entry {
			let children = dir.children.read().unwrap();
			for (k, v) in children.iter() {
				let stat = v.stat().read().unwrap();
				let res = fill_find_data(&FindData {
					attributes: stat.attrs,
					creation_time: stat.ctime,
					last_access_time: stat.mtime,
					last_write_time: stat.mtime,
					file_size: match v {
						Entry::File(file) => file.data.read().unwrap().len() as u64,
						Entry::Directory(_) => 0,
					},
					file_name: U16CString::from_ustr(&k.0).unwrap(),
				});
				match res {
					Ok(()) => (),
					Err(FillDataError::BufferFull) => return nt_res(STATUS_INTERNAL_ERROR),
					// Silently ignore this error because 1) file names passed to create_file should have been checked
					// by Windows. 2) We don't want an error on a single file to make the whole directory unreadable.
					Err(FillDataError::NameTooLong) => (),
				}
			}
			Ok(())
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		}
	}

	fn set_file_attributes(
		&'b self,
		_file_name: &U16CStr,
		file_attributes: u32,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		const SUPPORTED_ATTRS: u32 = winnt::FILE_ATTRIBUTE_ARCHIVE | winnt::FILE_ATTRIBUTE_HIDDEN
			| winnt::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | winnt::FILE_ATTRIBUTE_OFFLINE | winnt::FILE_ATTRIBUTE_READONLY
			| winnt::FILE_ATTRIBUTE_SYSTEM | winnt::FILE_ATTRIBUTE_TEMPORARY;
		let mut stat = context.entry.stat().write().unwrap();
		stat.attrs = canonicalize_attrs(
			(stat.attrs & !SUPPORTED_ATTRS) | (file_attributes & SUPPORTED_ATTRS),
			info.is_dir(),
		);
		Ok(())
	}

	fn set_file_time(
		&'b self,
		_file_name: &U16CStr,
		creation_time: SystemTime,
		_last_access_time: SystemTime,
		last_write_time: SystemTime,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		let mut stat = context.entry.stat().write().unwrap();
		stat.ctime = creation_time;
		stat.mtime = last_write_time;
		Ok(())
	}

	fn delete_file(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		context.entry.stat().write().unwrap().delete_pending = info.delete_on_close();
		Ok(())
	}


	fn delete_directory(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		if let Entry::Directory(dir) = &context.entry {
			// Lock children first to avoid race conditions.
			let children = dir.children.read().unwrap();
			let mut stat = dir.stat.write().unwrap();
			if stat.parent.upgrade().is_none() {
				// Root directory can't be deleted.
				return nt_res(STATUS_ACCESS_DENIED);
			}
			if info.delete_on_close() && !children.is_empty() {
				nt_res(STATUS_DIRECTORY_NOT_EMPTY)
			} else {
				stat.delete_pending = info.delete_on_close();
				Ok(())
			}
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		}
	}

	fn move_file(
		&'b self,
		file_name: &U16CStr,
		new_file_name: &U16CStr,
		replace_if_existing: bool,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		let src_path = file_name.as_slice();
		let offset = src_path.iter().rposition(|x| *x == '\\' as u16)
			.ok_or(nt_err(STATUS_INVALID_PARAMETER))?;
		let src_name = U16Str::from_slice(&src_path[offset + 1..]);
		let src_parent = context.entry.stat().read().unwrap().parent.upgrade().unwrap();
		let (dst_name, dst_parent) = self.split_path(new_file_name)?
			.ok_or(nt_err(STATUS_INVALID_PARAMETER))?;
		if Arc::ptr_eq(&src_parent, &dst_parent) {
			let mut children = src_parent.children.write().unwrap();
			children.remove(EntryNameRef::new(src_name)).unwrap();
			assert_eq!(children.insert(EntryName(dst_name.to_owned()), context.entry.clone()), None);
		} else {
			let mut src_children = src_parent.children.write().unwrap();
			let mut dst_children = dst_parent.children.write().unwrap();
			match dst_children.entry(EntryName(dst_name.to_owned())) {
				hash_map::Entry::Occupied(mut occupied_entry) => {
					if !replace_if_existing {
						return nt_res(STATUS_OBJECT_NAME_COLLISION);
					}
					if occupied_entry.get().stat().read().unwrap().handle_count > 1 {
						return nt_res(STATUS_ACCESS_DENIED);
					}
					occupied_entry.insert(context.entry.clone());
				}
				hash_map::Entry::Vacant(vacant_entry) => {
					vacant_entry.insert(context.entry.clone());
				}
			}
			src_children.remove(EntryNameRef::new(src_name)).unwrap();
			context.entry.stat().write().unwrap().parent = Arc::downgrade(&dst_parent);
		}
		Ok(())
	}

	fn set_end_of_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		if let Entry::File(file) = &context.entry {
			file.data.write().unwrap().resize(offset as usize, 0);
			Ok(())
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		}
	}

	fn set_allocation_size(
		&'b self,
		_file_name: &U16CStr,
		alloc_size: i64,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		if let Entry::File(file) = &context.entry {
			let alloc_size = alloc_size as usize;
			let mut data = file.data.write().unwrap();
			let cap = data.capacity();
			if alloc_size < data.len() {
				data.resize(alloc_size, 0);
			} else if alloc_size < cap {
				let mut new_data = Vec::with_capacity(alloc_size);
				new_data.append(&mut data);
				*data = new_data;
			} else if alloc_size > cap {
				data.reserve(alloc_size - cap);
			}
			Ok(())
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		}
	}

	fn get_disk_free_space(
		&'b self,
		_info: &OperationInfo<'a, 'b, Self>,
	) -> Result<DiskSpaceInfo, OperationError> {
		Ok(DiskSpaceInfo {
			byte_count: 1024 * 1024 * 1024,
			free_byte_count: 512 * 1024 * 1024,
			available_byte_count: 512 * 1024 * 1024,
		})
	}


	fn get_volume_information(
		&'b self,
		_info: &OperationInfo<'a, 'b, Self>,
	) -> Result<VolumeInfo, OperationError> {
		Ok(VolumeInfo {
			name: U16CString::from_str("dokan-rust memfs").unwrap(),
			serial_number: 0,
			// Use the same value as NTFS.
			max_component_length: 255,
			fs_flags: winnt::FILE_CASE_PRESERVED_NAMES | winnt::FILE_CASE_SENSITIVE_SEARCH | winnt::FILE_UNICODE_ON_DISK
				| winnt::FILE_PERSISTENT_ACLS,
			// Custom names don't play well with UAC.
			fs_name: U16CString::from_str("NTFS").unwrap(),
		})
	}

	fn get_file_security(
		&'b self,
		_file_name: &U16CStr,
		security_information: u32,
		security_descriptor: winnt::PSECURITY_DESCRIPTOR,
		buffer_length: u32,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<u32, OperationError> {
		context.entry.stat().read().unwrap().sec_desc
			.get_security_info(security_information, security_descriptor, buffer_length)
	}

	fn set_file_security(
		&'b self,
		_file_name: &U16CStr,
		security_information: u32,
		security_descriptor: winnt::PSECURITY_DESCRIPTOR,
		_buffer_length: u32,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		context.entry.stat().write().unwrap().sec_desc.set_security_info(security_information, security_descriptor)
	}

	// TODO: Support find_streams
}

fn main() -> Result<(), MountError> {
	let mount_point = U16CString::from_str("Z").unwrap();
	Drive::new()
		.mount_point(&mount_point)
		.mount(&MemFsHandler::new())
}
