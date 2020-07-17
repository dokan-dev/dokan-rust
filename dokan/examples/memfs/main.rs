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
use winapi::shared::{ntdef, ntstatus::*};
use winapi::um::winnt;

mod security;
mod err_utils;
mod path;

use security::SecurityDescriptor;
use err_utils::*;
use crate::path::FullName;

#[derive(Debug)]
struct AltStream {
	handle_count: u32,
	delete_pending: bool,
	data: Vec<u8>,
}

impl AltStream {
	fn new() -> Self {
		Self {
			handle_count: 0,
			delete_pending: false,
			data: Vec::new(),
		}
	}
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
struct Attributes {
	value: u32,
}

impl Attributes {
	fn new(attrs: u32) -> Self {
		const SUPPORTED_ATTRS: u32 = winnt::FILE_ATTRIBUTE_ARCHIVE | winnt::FILE_ATTRIBUTE_HIDDEN
			| winnt::FILE_ATTRIBUTE_NOT_CONTENT_INDEXED | winnt::FILE_ATTRIBUTE_OFFLINE | winnt::FILE_ATTRIBUTE_READONLY
			| winnt::FILE_ATTRIBUTE_SYSTEM | winnt::FILE_ATTRIBUTE_TEMPORARY;
		Self { value: attrs & SUPPORTED_ATTRS }
	}

	fn get_output_attrs(&self, is_dir: bool) -> u32 {
		let mut attrs = self.value;
		if is_dir {
			attrs |= winnt::FILE_ATTRIBUTE_DIRECTORY;
		}
		if attrs == 0 {
			attrs = winnt::FILE_ATTRIBUTE_NORMAL
		}
		attrs
	}
}


#[derive(Debug)]
struct Stat {
	id: u64,
	attrs: Attributes,
	ctime: SystemTime,
	mtime: SystemTime,
	sec_desc: SecurityDescriptor,
	handle_count: u32,
	delete_pending: bool,
	parent: Weak<DirEntry>,
	alt_streams: HashMap<EntryName, Arc<RwLock<AltStream>>>,
}

impl Stat {
	fn new(id: u64, attrs: u32, sec_desc: SecurityDescriptor, parent: Weak<DirEntry>) -> Self {
		let now = SystemTime::now();
		Self {
			id,
			attrs: Attributes::new(attrs),
			ctime: now,
			mtime: now,
			sec_desc,
			handle_count: 0,
			delete_pending: false,
			parent,
			alt_streams: HashMap::new(),
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

#[derive(Debug)]
struct FileEntry {
	stat: RwLock<Stat>,
	data: RwLock<Vec<u8>>,
}

impl FileEntry {
	fn new(stat: Stat) -> Self {
		Self {
			stat: RwLock::new(stat),
			data: RwLock::new(Vec::new()),
		}
	}
}

// The compiler incorrectly believes that its usage in a public function of the private path module is public.
#[derive(Debug)]
pub struct DirEntry {
	stat: RwLock<Stat>,
	children: RwLock<HashMap<EntryName, Entry>>,
}

impl DirEntry {
	fn new(stat: Stat) -> Self {
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

	fn is_dir(&self) -> bool {
		match self {
			Entry::File(_) => false,
			Entry::Directory(_) => true,
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
	alt_stream: Option<Arc<RwLock<AltStream>>>,
	delete_on_close: bool,
}

impl EntryHandle {
	fn new(entry: Entry, alt_stream: Option<Arc<RwLock<AltStream>>>, delete_on_close: bool) -> Self {
		entry.stat().write().unwrap().handle_count += 1;
		if let Some(s) = &alt_stream {
			s.write().unwrap().handle_count += 1;
		}
		Self {
			entry,
			alt_stream,
			delete_on_close,
		}
	}

	fn is_dir(&self) -> bool {
		if self.alt_stream.is_some() { false } else { self.entry.is_dir() }
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
			parent.as_ref().unwrap().stat.write().unwrap().mtime = SystemTime::now();
			let mut parent_children = parent_children.unwrap();
			let key = parent_children.iter().find_map(|(k, v)| {
				if &self.entry == v { Some(k) } else { None }
			}).unwrap().clone();
			parent_children.remove(Borrow::<EntryNameRef>::borrow(&key)).unwrap();
		} else {
			// Ignore root directory.
			stat.delete_pending = false
		}
		if let Some(stream) = &self.alt_stream {
			stat.mtime = SystemTime::now();
			let mut stream_locked = stream.write().unwrap();
			stream_locked.handle_count -= 1;
			if stream_locked.delete_pending && stream_locked.handle_count == 0 {
				let key = stat.alt_streams.iter().find_map(|(k, v)| {
					if Arc::ptr_eq(stream, v) { Some(k) } else { None }
				}).unwrap().clone();
				stat.alt_streams.remove(Borrow::<EntryNameRef>::borrow(&key)).unwrap();
			}
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

	fn next_id(&self) -> u64 {
		self.id_counter.fetch_add(1, Ordering::Relaxed)
	}

	fn create_new(
		&self,
		name: &FullName,
		attrs: u32,
		delete_on_close: bool,
		creator_desc: winnt::PSECURITY_DESCRIPTOR,
		token: ntdef::HANDLE,
		parent: &Arc<DirEntry>,
		children: &mut HashMap<EntryName, Entry>,
		is_dir: bool,
	) -> Result<CreateFileInfo<EntryHandle>, OperationError> {
		let mut stat = Stat::new(
			self.next_id(),
			attrs,
			SecurityDescriptor::new_inherited(
				&parent.stat.read().unwrap().sec_desc,
				creator_desc, token, is_dir,
			)?,
			Arc::downgrade(&parent),
		);
		let stream = if let Some(stream_info) = &name.stream_info {
			if stream_info.check_default(is_dir)? { None } else {
				let stream = Arc::new(RwLock::new(AltStream::new()));
				assert!(stat.alt_streams
					.insert(EntryName(stream_info.name.to_owned()), Arc::clone(&stream))
					.is_none());
				Some(stream)
			}
		} else { None };
		let entry = if is_dir {
			Entry::Directory(Arc::new(DirEntry::new(stat)))
		} else {
			Entry::File(Arc::new(FileEntry::new(stat)))
		};
		assert!(children
			.insert(EntryName(name.file_name.to_owned()), entry.clone())
			.is_none());
		parent.stat.write().unwrap().mtime = SystemTime::now();
		let is_dir = is_dir && stream.is_some();
		Ok(CreateFileInfo {
			context: EntryHandle::new(entry, stream, delete_on_close),
			is_dir,
			new_file_created: true,
		})
	}
}

fn check_fill_data_error(res: Result<(), FillDataError>) -> Result<(), OperationError> {
	match res {
		Ok(()) => Ok(()),
		Err(FillDataError::BufferFull) => nt_res(STATUS_INTERNAL_ERROR),
		// Silently ignore this error because 1) file names passed to create_file should have been checked
		// by Windows. 2) We don't want an error on a single file to make the whole directory unreadable.
		Err(FillDataError::NameTooLong) => Ok(()),
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
		desired_access: winnt::ACCESS_MASK,
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
		let path_info = path::split_path(&self.root, file_name)?;
		if let Some((name, parent)) = path_info {
			let mut children = parent.children.write().unwrap();
			if let Some(entry) = children.get(EntryNameRef::new(name.file_name)) {
				let stat = entry.stat().read().unwrap();
				let is_readonly = stat.attrs.value & winnt::FILE_ATTRIBUTE_READONLY > 0;
				if is_readonly && desired_access & winnt::FILE_GENERIC_WRITE > 0 || stat.delete_pending {
					return nt_res(STATUS_ACCESS_DENIED);
				}
				std::mem::drop(stat);
				let ret = if let Some(stream_info) = &name.stream_info {
					if stream_info.check_default(entry.is_dir())? { None } else {
						let mut stat = entry.stat().write().unwrap();
						let stream_name = EntryNameRef::new(stream_info.name);
						if let Some(stream) = stat.alt_streams
							.get(stream_name)
							.map(|s| Arc::clone(s))
						{
							if stream.read().unwrap().delete_pending {
								return nt_res(STATUS_ACCESS_DENIED);
							}
							match create_disposition {
								FILE_SUPERSEDE | FILE_OVERWRITE | FILE_OVERWRITE_IF => {
									if is_readonly {
										return nt_res(STATUS_ACCESS_DENIED);
									}
									stat.mtime = SystemTime::now();
									stream.write().unwrap().data.clear();
								}
								FILE_CREATE => return nt_res(STATUS_OBJECT_NAME_COLLISION),
								_ => (),
							}
							Some((stream, false))
						} else {
							if create_disposition == FILE_OPEN || create_disposition == FILE_OVERWRITE {
								return nt_res(STATUS_OBJECT_NAME_NOT_FOUND);
							}
							if is_readonly {
								return nt_res(STATUS_ACCESS_DENIED);
							}
							let stream = Arc::new(RwLock::new(AltStream::new()));
							stat.mtime = SystemTime::now();
							assert!(stat.alt_streams
								.insert(EntryName(stream_info.name.to_owned()), Arc::clone(&stream))
								.is_none());
							Some((stream, true))
						}
					}
				} else { None };
				if let Some((stream, new_file_created)) = ret {
					return Ok(CreateFileInfo {
						context: EntryHandle::new(entry.clone(), Some(stream), delete_on_close),
						is_dir: false,
						new_file_created,
					});
				}
				match entry {
					Entry::File(file) => {
						if create_options & FILE_DIRECTORY_FILE > 0 {
							return nt_res(STATUS_NOT_A_DIRECTORY);
						}
						match create_disposition {
							FILE_SUPERSEDE => {
								if is_readonly {
									return nt_res(STATUS_ACCESS_DENIED);
								}
								let token = info.requester_token().unwrap();
								let mut stat = file.stat.write().unwrap();
								let id = stat.id;
								*stat = Stat::new(
									id,
									file_attributes,
									SecurityDescriptor::new_inherited(
										&parent.stat.read().unwrap().sec_desc,
										creator_desc, token.as_raw_handle(), false,
									)?,
									Arc::downgrade(&parent),
								);
								file.data.write().unwrap().clear();
							}
							FILE_OVERWRITE | FILE_OVERWRITE_IF => {
								if is_readonly {
									return nt_res(STATUS_ACCESS_DENIED);
								}
								file.stat.write().unwrap().mtime = SystemTime::now();
								file.data.write().unwrap().clear();
							}
							FILE_CREATE => return nt_res(STATUS_OBJECT_NAME_COLLISION),
							_ => (),
						}
						Ok(CreateFileInfo {
							context: EntryHandle::new(Entry::File(Arc::clone(file)), None, delete_on_close),
							is_dir: false,
							new_file_created: false,
						})
					}
					Entry::Directory(dir) => {
						if create_options & FILE_NON_DIRECTORY_FILE > 0 {
							return nt_res(STATUS_FILE_IS_A_DIRECTORY);
						}
						match create_disposition {
							FILE_OPEN | FILE_OPEN_IF => {
								Ok(CreateFileInfo {
									context: EntryHandle::new(Entry::Directory(Arc::clone(dir)), None, delete_on_close),
									is_dir: true,
									new_file_created: false,
								})
							}
							FILE_CREATE => nt_res(STATUS_OBJECT_NAME_COLLISION),
							_ => nt_res(STATUS_INVALID_PARAMETER),
						}
					}
				}
			} else {
				if parent.stat.read().unwrap().delete_pending {
					return nt_res(STATUS_ACCESS_DENIED);
				}
				let token = info.requester_token().unwrap();
				if create_options & FILE_DIRECTORY_FILE > 0 {
					match create_disposition {
						FILE_CREATE | FILE_OPEN_IF => {
							self.create_new(
								&name, file_attributes, delete_on_close, creator_desc, token.as_raw_handle(),
								&parent, &mut children, true,
							)
						}
						FILE_OPEN => nt_res(STATUS_OBJECT_NAME_NOT_FOUND),
						_ => nt_res(STATUS_INVALID_PARAMETER),
					}
				} else {
					if create_disposition == FILE_OPEN || create_disposition == FILE_OVERWRITE {
						nt_res(STATUS_OBJECT_NAME_NOT_FOUND)
					} else {
						self.create_new(
							&name, file_attributes, delete_on_close, creator_desc, token.as_raw_handle(),
							&parent, &mut children, false,
						)
					}
				}
			}
		} else {
			if create_disposition == FILE_OPEN || create_disposition == FILE_OPEN_IF {
				if create_options & FILE_NON_DIRECTORY_FILE > 0 {
					nt_res(STATUS_FILE_IS_A_DIRECTORY)
				} else {
					Ok(CreateFileInfo {
						context: EntryHandle::new(
							Entry::Directory(Arc::clone(&self.root)),
							None, info.delete_on_close(),
						),
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
		let mut do_read = |data: &Vec<_>| {
			let offset = offset as usize;
			let len = std::cmp::min(buffer.len(), data.len() - offset);
			buffer[0..len].copy_from_slice(&data[offset..offset + len]);
			len as u32
		};
		if let Some(stream) = &context.alt_stream {
			Ok(do_read(&stream.read().unwrap().data))
		} else if let Entry::File(file) = &context.entry {
			Ok(do_read(&file.data.read().unwrap()))
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
		let do_write = |data: &mut Vec<_>| {
			let offset = if info.write_to_eof() { data.len() } else { offset as usize };
			let len = buffer.len();
			if offset + len > data.len() {
				data.resize(offset + len, 0);
			}
			data[offset..offset + len].copy_from_slice(buffer);
			len as u32
		};
		let ret = if let Some(stream) = &context.alt_stream {
			Ok(do_write(&mut stream.write().unwrap().data))
		} else if let Entry::File(file) = &context.entry {
			Ok(do_write(&mut file.data.write().unwrap()))
		} else {
			nt_res(STATUS_ACCESS_DENIED)
		};
		if ret.is_ok() {
			context.entry.stat().write().unwrap().mtime = SystemTime::now();
		}
		ret
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
			attributes: stat.attrs.get_output_attrs(context.is_dir()),
			creation_time: stat.ctime,
			last_access_time: stat.mtime,
			last_write_time: stat.mtime,
			file_size: if let Some(stream) = &context.alt_stream {
				stream.read().unwrap().data.len() as u64
			} else {
				match &context.entry {
					Entry::File(file) => file.data.read().unwrap().len() as u64,
					Entry::Directory(_) => 0,
				}
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
		if context.alt_stream.is_some() {
			return nt_res(STATUS_INVALID_DEVICE_REQUEST);
		}
		if let Entry::Directory(dir) = &context.entry {
			let children = dir.children.read().unwrap();
			for (k, v) in children.iter() {
				let stat = v.stat().read().unwrap();
				let res = fill_find_data(&FindData {
					attributes: stat.attrs.get_output_attrs(v.is_dir()),
					creation_time: stat.ctime,
					last_access_time: stat.mtime,
					last_write_time: stat.mtime,
					file_size: match v {
						Entry::File(file) => file.data.read().unwrap().len() as u64,
						Entry::Directory(_) => 0,
					},
					file_name: U16CString::from_ustr(&k.0).unwrap(),
				});
				check_fill_data_error(res)?;
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
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		context.entry.stat().write().unwrap().attrs = Attributes::new(file_attributes);
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
		if let Some(stream) = &context.alt_stream {
			stream.write().unwrap().delete_pending = info.delete_on_close();
		} else {
			context.entry.stat().write().unwrap().delete_pending = info.delete_on_close();
		}
		Ok(())
	}


	fn delete_directory(
		&'b self,
		_file_name: &U16CStr,
		info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		if context.alt_stream.is_some() {
			return nt_res(STATUS_INVALID_DEVICE_REQUEST);
		}
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
		if context.alt_stream.is_some() {
			return nt_res(STATUS_INVALID_DEVICE_REQUEST);
		}
		let src_path = file_name.as_slice();
		let offset = src_path.iter().rposition(|x| *x == '\\' as u16)
			.ok_or(nt_err(STATUS_INVALID_PARAMETER))?;
		let src_name = U16Str::from_slice(&src_path[offset + 1..]);
		let src_parent = context.entry.stat().read().unwrap().parent.upgrade().unwrap();
		let (dst_name, dst_parent) = path::split_path(&self.root, new_file_name)?
			.ok_or(nt_err(STATUS_INVALID_PARAMETER))?;
		if dst_name.stream_info.is_some() {
			return nt_res(STATUS_OBJECT_NAME_INVALID);
		}
		if Arc::ptr_eq(&src_parent, &dst_parent) {
			let mut children = src_parent.children.write().unwrap();
			children.remove(EntryNameRef::new(src_name)).unwrap();
			assert_eq!(children.insert(EntryName(dst_name.file_name.to_owned()), context.entry.clone()), None);
		} else {
			let mut src_children = src_parent.children.write().unwrap();
			let mut dst_children = dst_parent.children.write().unwrap();
			match dst_children.entry(EntryName(dst_name.file_name.to_owned())) {
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
		let now = SystemTime::now();
		src_parent.stat.write().unwrap().mtime = now;
		dst_parent.stat.write().unwrap().mtime = now;
		Ok(())
	}

	fn set_end_of_file(
		&'b self,
		_file_name: &U16CStr,
		offset: i64,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		let ret = if let Some(stream) = &context.alt_stream {
			stream.write().unwrap().data.resize(offset as usize, 0);
			Ok(())
		} else if let Entry::File(file) = &context.entry {
			file.data.write().unwrap().resize(offset as usize, 0);
			Ok(())
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		};
		if ret.is_ok() {
			context.entry.stat().write().unwrap().mtime = SystemTime::now();
		}
		ret
	}

	fn set_allocation_size(
		&'b self,
		_file_name: &U16CStr,
		alloc_size: i64,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		let set_alloc = |data: &mut Vec<_>| {
			let alloc_size = alloc_size as usize;
			let cap = data.capacity();
			if alloc_size < data.len() {
				data.resize(alloc_size, 0);
			} else if alloc_size < cap {
				let mut new_data = Vec::with_capacity(alloc_size);
				new_data.append(data);
				*data = new_data;
			} else if alloc_size > cap {
				data.reserve(alloc_size - cap);
			}
		};
		let ret = if let Some(stream) = &context.alt_stream {
			set_alloc(&mut stream.write().unwrap().data);
			Ok(())
		} else if let Entry::File(file) = &context.entry {
			set_alloc(&mut file.data.write().unwrap());
			Ok(())
		} else {
			nt_res(STATUS_INVALID_DEVICE_REQUEST)
		};
		if ret.is_ok() {
			context.entry.stat().write().unwrap().mtime = SystemTime::now();
		}
		ret
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
				| winnt::FILE_PERSISTENT_ACLS | winnt::FILE_NAMED_STREAMS,
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

	fn find_streams(
		&'b self,
		_file_name: &U16CStr,
		mut fill_find_stream_data: impl FnMut(&FindStreamData) -> Result<(), FillDataError>,
		_info: &OperationInfo<'a, 'b, Self>,
		context: &'a Self::Context,
	) -> Result<(), OperationError> {
		if let Entry::File(file) = &context.entry {
			let res = fill_find_stream_data(&FindStreamData {
				size: file.data.read().unwrap().len() as i64,
				name: U16CString::from_str("::$DATA").unwrap(),
			});
			check_fill_data_error(res)?;
		}
		for (k, v) in context.entry.stat().read().unwrap().alt_streams.iter() {
			let mut name_buf = vec![':' as u16];
			name_buf.extend_from_slice(k.0.as_slice());
			name_buf.extend_from_slice(U16String::from_str(":$DATA").as_slice());
			let res = fill_find_stream_data(&FindStreamData {
				size: v.read().unwrap().data.len() as i64,
				name: U16CString::from_ustr(U16Str::from_slice(&name_buf)).unwrap(),
			});
			check_fill_data_error(res)?;
		}
		Ok(())
	}
}

fn main() -> Result<(), MountError> {
	let mount_point = U16CString::from_str("Z").unwrap();
	Drive::new()
		.mount_point(&mount_point)
		.flags(MountFlags::ALT_STREAM)
		.mount(&MemFsHandler::new())
}
