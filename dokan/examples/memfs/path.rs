use std::borrow::Borrow;
use std::sync::Arc;

use dokan::OperationError;
use widestring::{U16CStr, U16Str, U16String};
use winapi::shared::ntstatus::*;

use crate::{DirEntry, Entry, EntryName, EntryNameRef};
use crate::err_utils::*;

// Use the same value as NTFS.
pub const MAX_COMPONENT_LENGTH: u32 = 255;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum StreamType {
	Data,
	IndexAllocation,
	Bitmap,
}

#[derive(Debug)]
pub struct StreamInfo<'a> {
	pub name: &'a U16Str,
	pub type_: StreamType,
}

impl StreamInfo<'_> {
	pub fn check_default(&self, is_dir: bool) -> Result<bool, OperationError> {
		if is_dir {
			if self.name.is_empty() || EntryNameRef::new(self.name) == EntryName(U16String::from_str("$I30")).borrow() {
				if self.type_ == StreamType::IndexAllocation {
					Ok(true)
				} else {
					nt_res(STATUS_OBJECT_NAME_INVALID)
				}
			} else if self.type_ == StreamType::Data {
				Ok(false)
			} else {
				nt_res(STATUS_OBJECT_NAME_INVALID)
			}
		} else if self.type_ == StreamType::Data {
			Ok(self.name.is_empty())
		} else {
			nt_res(STATUS_OBJECT_NAME_INVALID)
		}
	}
}

#[derive(Debug)]
pub struct FullName<'a> {
	pub file_name: &'a U16Str,
	pub stream_info: Option<StreamInfo<'a>>,
}

impl<'a> FullName<'a> {
	fn new(name: &'a U16Str) -> Result<Self, OperationError> {
		let name_slice = name.as_slice();
		if let Some(offset1) = name_slice.iter().position(|x| *x == ':' as u16) {
			let file_name = U16Str::from_slice(&name_slice[..offset1]);
			let stream_info = &name_slice[offset1 + 1..];
			if let Some(offset2) = stream_info.iter().position(|x| *x == ':' as u16) {
				let stream_type_str = EntryNameRef::new(U16Str::from_slice(&stream_info[offset2 + 1..]));
				let stream_type = if stream_type_str == EntryName(U16String::from_str("$DATA")).borrow() {
					StreamType::Data
				} else if stream_type_str == EntryName(U16String::from_str("$INDEX_ALLOCATION")).borrow() {
					StreamType::IndexAllocation
				} else if stream_type_str == EntryName(U16String::from_str("$BITMAP")).borrow() {
					StreamType::Bitmap
				} else {
					return nt_res(STATUS_OBJECT_NAME_INVALID);
				};
				Ok(Self {
					file_name,
					stream_info: Some(StreamInfo {
						name: U16Str::from_slice(&stream_info[..offset2]),
						type_: stream_type,
					}),
				})
			} else {
				Ok(Self {
					file_name,
					stream_info: Some(StreamInfo {
						name: U16Str::from_slice(stream_info),
						type_: StreamType::Data,
					}),
				})
			}
		} else {
			Ok(Self {
				file_name: name,
				stream_info: None,
			})
		}
	}
}

fn find_dir_entry(cur_entry: &Arc<DirEntry>, path: &[&U16Str]) -> Result<Arc<DirEntry>, OperationError> {
	if let Some(name) = path.get(0) {
		if name.len() > MAX_COMPONENT_LENGTH as usize {
			return nt_res(STATUS_OBJECT_NAME_INVALID);
		}
		match cur_entry.children.read().unwrap().get(EntryNameRef::new(name)) {
			Some(Entry::Directory(dir)) => find_dir_entry(dir, &path[1..]),
			_ => nt_res(STATUS_OBJECT_PATH_NOT_FOUND)
		}
	} else {
		Ok(Arc::clone(cur_entry))
	}
}

pub fn split_path<'a>(
	root: &Arc<DirEntry>,
	path: &'a U16CStr,
) -> Result<Option<(FullName<'a>, Arc<DirEntry>)>, OperationError> {
	let path = path.as_slice()
		.split(|x| *x == '\\' as u16)
		.filter(|s| !s.is_empty())
		.map(|s| U16Str::from_slice(s))
		.collect::<Vec<_>>();
	if path.is_empty() { Ok(None) } else {
		let name = *path.iter().last().unwrap();
		if name.len() > MAX_COMPONENT_LENGTH as usize {
			return nt_res(STATUS_OBJECT_NAME_INVALID);
		}
		Ok(Some((
			FullName::new(name)?,
			find_dir_entry(root, &path[..path.len() - 1])?
		)))
	}
}
