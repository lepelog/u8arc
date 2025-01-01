use std::{
    borrow::{BorrowMut, Cow},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    ops::Neg,
};

use binrw::{binrw, BinReaderExt, BinWriterExt};

#[derive(Debug)]
pub enum Entry {
    DirEntry { name: String, files: Vec<Entry> },
    FileEntry { name: String, data: FileEntry },
}

#[derive(Debug)]
pub enum FileEntry {
    Ref { offset: u32, length: u32 },
    Data(Vec<u8>),
}

pub struct U8Arc<'a> {
    data: Cow<'a, [u8]>,
    root: Vec<Entry>,
}

#[derive(thiserror::Error, Debug)]
pub enum U8ParseError {
    #[error("unexpected EOF")]
    UnexpectedEoF,
    #[error("invalid node")]
    InvalidNode,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("invalid node decoding")]
    InvalidNodeDecoding,
    #[error("binrw error {0}")]
    BinRw(binrw::Error),
}

impl From<std::io::Error> for U8ParseError {
    fn from(_: std::io::Error) -> Self {
        U8ParseError::UnexpectedEoF
    }
}

impl From<binrw::Error> for U8ParseError {
    fn from(e: binrw::Error) -> Self {
        U8ParseError::BinRw(e)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum U8SetDataError {
    #[error("file doesn't exist")]
    FileNotExist,
    #[error("path is a directory")]
    IsDirectory,
}

fn read_u24(data: [u8; 3]) -> u32 {
    u32::from_be_bytes([0, data[0], data[1], data[2]])
}

fn write_u24(data: &u32) -> [u8; 3] {
    let b = data.to_be_bytes();
    [b[1], b[2], b[3]]
}

#[derive(Debug)]
#[binrw]
#[brw(magic = b"U\xaa8-")]
#[br(assert(header_size == 0x20))]
struct U8Header {
    header_size: u32,
    node_and_string_pool_size: u32,
    #[brw(pad_after = 0x10)]
    data_offset: u32,
}

#[derive(Debug)]
#[binrw]
enum RawNode {
    #[brw(magic(0u8))]
    RawFileNode {
        #[br(map = read_u24)]
        #[bw(map = write_u24)]
        string_offset: u32,
        data_start: u32,
        data_size: u32,
    },
    #[brw(magic(1u8))]
    RawDirNode {
        #[br(map = read_u24)]
        #[bw(map = write_u24)]
        string_offset: u32,
        parent_index: u32,
        next_parent_index: u32,
    },
}

impl RawNode {
    const SIZE: u32 = 0xC;

    fn get_string_offset(&self) -> u32 {
        match self {
            RawNode::RawFileNode { string_offset, .. } => *string_offset,
            RawNode::RawDirNode { string_offset, .. } => *string_offset,
        }
    }
}

fn read_ascii<RS: Read + Seek>(data: &mut RS, pos: u32) -> Result<String, U8ParseError> {
    data.seek(SeekFrom::Start(pos.into()))?;
    let mut buf = Vec::new();
    loop {
        let read = data.read_be::<u8>()?;
        if read == 0 {
            break;
        }
        if !read.is_ascii() {
            return Err(U8ParseError::InvalidNodeDecoding);
        }
        buf.push(read);
    }

    String::from_utf8(buf).map_err(|_| U8ParseError::InvalidNodeDecoding)
}

impl Entry {
    pub fn is_dir(&self) -> bool {
        matches!(self, Entry::DirEntry { .. })
    }

    pub fn is_ref(&self) -> bool {
        matches!(
            self,
            Entry::FileEntry {
                data: FileEntry::Ref { .. },
                ..
            }
        )
    }

    pub fn is_data(&self) -> bool {
        matches!(
            self,
            Entry::FileEntry {
                data: FileEntry::Data(..),
                ..
            }
        )
    }

    pub fn get_name(&self) -> &String {
        match self {
            Self::DirEntry { name, .. } => name,
            Self::FileEntry { name, .. } => name,
        }
    }

    pub fn set_name(&mut self, new_name: String) {
        match self {
            Self::DirEntry { name, .. } => *name = new_name,
            Self::FileEntry { name, .. } => *name = new_name,
        }
    }
}

fn insert_entry_rec<'a>(
    current_entry: &mut Entry,
    mut parts: impl Iterator<Item = &'a str>,
    data: Vec<u8>,
) -> Option<Entry> {
    let Some(current_part) = parts.next() else {
        let mut new_entry = Entry::FileEntry {
            name: current_entry.get_name().clone(),
            data: FileEntry::Data(data),
        };
        std::mem::swap(current_entry, &mut new_entry);
        return Some(new_entry);
    };
    match current_entry {
        Entry::FileEntry { .. } => None,
        Entry::DirEntry { files, .. } => {
            if let Some(entry) = files
                .iter_mut()
                .find(|entry| entry.get_name() == current_part)
            {
                insert_entry_rec(entry, parts, data)
            } else {
                let insert_pos = files
                    .binary_search_by_key(&current_part, |entry| entry.get_name())
                    .unwrap_err();
                files.insert(
                    insert_pos,
                    Entry::DirEntry {
                        name: current_part.to_string(),
                        files: Vec::new(),
                    },
                );
                insert_entry_rec(&mut files[insert_pos], parts, data)
            }
        }
    }
}

pub const MAGIC_HEADER: u32 = 0x55AA382D;

impl Default for U8Arc<'static> {
    fn default() -> Self {
        Self::new()
    }
}

impl U8Arc<'static> {
    pub fn new() -> Self {
        U8Arc {
            data: Cow::Borrowed(&[]),
            root: Vec::new(),
        }
    }

    pub fn read_vec(v: Vec<u8>) -> Result<Self, U8ParseError> {
        U8Arc::read_cow(Cow::Owned(v))
    }
}

impl<'a> U8Arc<'a> {
    /// reads a byte Vector into an U8Arc or returns an Error
    pub fn read(v: &'a [u8]) -> Result<Self, U8ParseError> {
        U8Arc::read_cow(Cow::Borrowed(v))
    }

    pub fn read_cow(v: Cow<'a, [u8]>) -> Result<Self, U8ParseError> {
        let mut c = Cursor::new(v);
        let header = c.read_be::<U8Header>()?;
        let first_node = c.read_be()?;

        let total_node_count = match first_node {
            RawNode::RawDirNode {
                next_parent_index, ..
            } => next_parent_index,
            _ => return Err(U8ParseError::InvalidNode),
        };

        let string_pool_offset = header.header_size + total_node_count * 12;

        // let root_node_name = read_ascii(&mut c, string_pool_offset)?;

        let root = read_nodes_recursive(
            &mut c,
            1,
            total_node_count,
            header.header_size,
            string_pool_offset,
        )?;

        Ok(U8Arc {
            root,
            data: c.into_inner(),
        })
    }

    pub fn get_root_entry(&self) -> &Vec<Entry> {
        &self.root
    }

    /// Gets the raw data for this archive
    /// empty for fresh archives
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    pub fn get_entry_data<'b>(&'b self, path: &str) -> Option<&'b [u8]> {
        self.get_entry(path)
            .and_then(|entry| self.get_data_from_entry(entry))
    }

    fn get_data_from_offset_len(&self, offset: u32, length: u32) -> &[u8] {
        &self.data[offset as usize..][..length as usize]
    }

    fn get_data_from_entry<'b>(&'b self, entry: &'b Entry) -> Option<&'b [u8]> {
        match entry {
            Entry::DirEntry { .. } => None,
            Entry::FileEntry {
                data: FileEntry::Data(data),
                ..
            } => Some(data),
            &Entry::FileEntry {
                data: FileEntry::Ref { offset, length },
                ..
            } => Some(&self.data[offset as usize..][..length as usize]),
        }
    }

    /// returns a reference to the entry specified by the path
    /// a starting "/" is ignored
    pub fn get_entry<'b>(&'b self, path: &str) -> Option<&'b Entry> {
        let mut parts_iter = path.split('/').peekable();
        // allow starting with leading slash or not
        if parts_iter.peek() == Some(&"") {
            parts_iter.next();
        }
        // get the first entry
        let first_part = parts_iter.next()?;
        let mut entry = self
            .root
            .iter()
            .find(|entry| entry.get_name() == first_part)?;
        for part in parts_iter {
            entry = match entry {
                Entry::DirEntry { files, .. } => {
                    files.iter().find(|entry| entry.get_name() == part)?
                }
                _ => return None,
            }
        }
        Some(entry)
    }

    /// returns a reference to the entry specified by the path
    /// a starting "/" is ignored
    pub fn get_entry_mut<'b>(&'b mut self, path: &str) -> Option<&'b mut Entry> {
        let mut parts_iter = path.split('/').peekable();
        // allow starting with leading slash or not
        if parts_iter.peek() == Some(&"") {
            parts_iter.next();
        }
        // get the first entry
        let first_part = parts_iter.next()?;
        let mut entry = self
            .root
            .iter_mut()
            .find(|entry| entry.get_name() == first_part)?;
        for part in parts_iter {
            entry = match entry {
                Entry::DirEntry { files, .. } => {
                    files.iter_mut().find(|entry| entry.get_name() == part)?
                }
                _ => return None,
            }
        }
        Some(entry.borrow_mut())
    }

    pub fn set_entry_data(&mut self, path: &str, new_data: Vec<u8>) -> Result<(), U8SetDataError> {
        let entry = self
            .get_entry_mut(path)
            .ok_or(U8SetDataError::FileNotExist)?;
        match entry {
            Entry::DirEntry { .. } => Err(U8SetDataError::IsDirectory),
            Entry::FileEntry { data, .. } => {
                *data = FileEntry::Data(new_data);
                Ok(())
            }
        }
    }

    /// Add the specified data at the specified path
    /// overwrites existing files without warning, also overwrites directories
    /// returns the entry previously at that position
    pub fn add_entry_data(&mut self, path: &str, new_data: Vec<u8>) -> Option<Entry> {
        let mut parts_iter = path.split('/').peekable();
        // allow starting with leading slash or not
        if parts_iter.peek() == Some(&"") {
            parts_iter.next();
        }
        // get the first entry
        let first_part = parts_iter.next()?;
        let entry = if let Some(entry) = self
            .root
            .iter_mut()
            .find(|entry| entry.get_name() == first_part)
        {
            entry
        } else {
            let insert_pos = self
                .root
                .binary_search_by_key(&first_part, |entry| entry.get_name())
                .unwrap_err();
            self.root.insert(
                insert_pos,
                Entry::DirEntry {
                    name: first_part.to_string(),
                    files: Vec::new(),
                },
            );
            &mut self.root[insert_pos]
        };
        insert_entry_rec(entry, parts_iter, new_data)
    }

    pub fn delete_entry(&mut self, path: &str) -> Option<Entry> {
        let mut parts_iter = path.split('/').peekable();
        // allow starting with leading slash or not
        if parts_iter.peek() == Some(&"") {
            parts_iter.next();
        }
        // get the first entry
        let mut entries = &mut self.root;
        while let Some(part) = parts_iter.next() {
            if parts_iter.peek().is_none() {
                // remove this part
                let idx = entries.iter().position(|entry| entry.get_name() == part)?;
                entries.remove(idx);
            } else {
                entries = match entries.iter_mut().find(|entry| entry.get_name() == part)? {
                    Entry::DirEntry { files, .. } => files,
                    Entry::FileEntry { .. } => return None,
                }
            }
        }
        None
    }

    /// returns all full paths as a Vector
    pub fn get_all_paths(&self) -> Vec<String> {
        let mut result = Vec::new();
        Self::collect_paths_rec("", &self.root, &mut result);
        result
    }

    fn collect_paths_rec(dir_stack: &str, files: &[Entry], collector: &mut Vec<String>) {
        for entry in files.iter() {
            let mut full_name = dir_stack.to_string();
            full_name.push('/');
            full_name.push_str(entry.get_name());
            match entry {
                Entry::DirEntry { files, .. } => {
                    Self::collect_paths_rec(&full_name, files, collector);
                }
                _ => {
                    collector.push(full_name);
                }
            }
        }
    }

    pub fn write<W: Write + Seek>(&self, w: &mut W) -> binrw::BinResult<()> {
        let mut rebuild_entries = Vec::new();
        let mut string_pool = Vec::new();
        // root node
        rebuild_entries.push(RebuildEntry::Dir {
            parent: 0,
            str_offset: 0,
            next_parent: 0, // filled in later
        });
        string_pool.push(0);

        // build structure for other nodes
        self.do_rebuild_rec(
            &self.root,
            0,
            &mut 0,
            &mut rebuild_entries,
            &mut string_pool,
        );
        let next_parent_pos = rebuild_entries.len() as u32;
        match rebuild_entries.get_mut(0).unwrap() {
            RebuildEntry::Dir { next_parent, .. } => {
                *next_parent = next_parent_pos;
            }
            _ => unreachable!(),
        }

        // size of nodes and string pool
        let node_and_string_pool_size =
            rebuild_entries.len() as u32 * RawNode::SIZE + string_pool.len() as u32;
        let unpadded_data_offset = 0x20 + node_and_string_pool_size;
        let data_offset =
            unpadded_data_offset + (unpadded_data_offset as isize).neg().rem_euclid(0x20) as u32;

        let header = U8Header {
            header_size: 0x20,
            node_and_string_pool_size,
            data_offset,
        };

        w.write_be(&header)?;

        // nodes
        for node in rebuild_entries.iter() {
            let raw_node = match node {
                &RebuildEntry::Dir {
                    str_offset,
                    parent,
                    next_parent,
                } => RawNode::RawDirNode {
                    string_offset: str_offset,
                    next_parent_index: next_parent,
                    parent_index: parent,
                },
                RebuildEntry::FileData {
                    str_offset,
                    new_offset,
                    data,
                    ..
                } => RawNode::RawFileNode {
                    string_offset: *str_offset,
                    data_start: data_offset + *new_offset,
                    data_size: data.len() as u32,
                },
            };
            w.write_be(&raw_node)?;
        }

        // string pool
        w.write_all(&string_pool)?;

        // actual data
        let mut current_pos = unpadded_data_offset;
        let padding = [0; 0x20];
        for node in rebuild_entries.iter() {
            let needed_padding = (current_pos as isize).neg().rem_euclid(0x20) as u32;
            w.write_all(&padding[..needed_padding as usize])?;
            current_pos += needed_padding;
            match node {
                RebuildEntry::Dir { .. } => continue,
                RebuildEntry::FileData {
                    data, new_offset, ..
                } => {
                    assert_eq!(current_pos, *new_offset + data_offset);
                    w.write_all(data)?;
                    current_pos += data.len() as u32;
                }
            }
        }

        Ok(())
    }

    pub fn write_to_vec(&self) -> binrw::BinResult<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.data.len());
        self.write(&mut Cursor::new(&mut buf))?;
        Ok(buf)
    }

    fn do_rebuild_rec<'b: 'a>(
        &'b self,
        files: &'b [Entry],
        parent: u32,
        data_offset: &mut u32,
        rebuild_entries: &mut Vec<RebuildEntry<'a>>,
        string_pool: &mut Vec<u8>,
    ) {
        for entry in files.iter() {
            let str_offset = string_pool.len() as u32;
            string_pool.extend(entry.get_name().as_bytes());
            string_pool.push(0);
            match entry {
                Entry::DirEntry {
                    files: sub_files, ..
                } => {
                    let current_entry_pos = rebuild_entries.len();
                    rebuild_entries.push(RebuildEntry::Dir {
                        next_parent: 0, // filled in later
                        parent,
                        str_offset,
                    });
                    self.do_rebuild_rec(
                        sub_files,
                        current_entry_pos as u32,
                        data_offset,
                        rebuild_entries,
                        string_pool,
                    );
                    let next_parent_pos = rebuild_entries.len() as u32;
                    match rebuild_entries.get_mut(current_entry_pos).unwrap() {
                        RebuildEntry::Dir { next_parent, .. } => {
                            *next_parent = next_parent_pos;
                        }
                        _ => unreachable!(),
                    }
                }
                &Entry::FileEntry {
                    data: FileEntry::Ref { offset, length },
                    ..
                } => {
                    let data = self.get_data_from_offset_len(offset, length);
                    rebuild_entries.push(RebuildEntry::FileData {
                        str_offset,
                        data,
                        new_offset: *data_offset,
                    });
                    *data_offset += length;
                    *data_offset += (*data_offset as isize).neg().rem_euclid(0x20) as u32;
                }
                Entry::FileEntry {
                    data: FileEntry::Data(data),
                    ..
                } => {
                    rebuild_entries.push(RebuildEntry::FileData {
                        str_offset,
                        data,
                        new_offset: *data_offset,
                    });
                    *data_offset += data.len() as u32;
                    *data_offset += (*data_offset as isize).neg().rem_euclid(0x20) as u32;
                }
            }
        }
    }
}

enum RebuildEntry<'a> {
    // str_offset is without the base stringpool offset
    // data offset is without the base data offset
    Dir {
        str_offset: u32,
        parent: u32,
        next_parent: u32,
    },
    FileData {
        str_offset: u32,
        data: &'a [u8],
        new_offset: u32,
    },
}

fn read_nodes_recursive<RS: Read + Seek>(
    data: &mut RS,
    start_idx: u32,
    end_index: u32,
    first_node_offset: u32,
    string_pool_offset: u32,
) -> Result<Vec<Entry>, U8ParseError> {
    let mut files = Vec::new();
    let mut cur_idx = start_idx;
    while cur_idx < end_index {
        data.seek(SeekFrom::Start((first_node_offset + cur_idx * 12).into()))?;
        let node: RawNode = data.read_be()?;
        let node_name = read_ascii(data, string_pool_offset + node.get_string_offset())?;

        match node {
            RawNode::RawDirNode {
                next_parent_index, ..
            } => {
                files.push(Entry::DirEntry {
                    name: node_name,
                    files: read_nodes_recursive(
                        data,
                        cur_idx + 1,
                        next_parent_index,
                        first_node_offset,
                        string_pool_offset,
                    )?,
                });
                cur_idx = next_parent_index;
            }
            RawNode::RawFileNode {
                data_size,
                data_start,
                ..
            } => {
                files.push(Entry::FileEntry {
                    name: node_name,
                    data: FileEntry::Ref {
                        offset: data_start,
                        length: data_size,
                    },
                });
                cur_idx += 1;
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod test {
    use std::fs::{metadata, read, read_dir};

    use crate::U8Arc;

    #[test]
    fn test_read() {
        for test_f in read_dir("../testfiles").unwrap() {
            let test_f_path = test_f.unwrap().path();

            if !metadata(&test_f_path).unwrap().is_file() {
                continue;
            }
            println!("reading {:?}", &test_f_path);
            let data = read(&test_f_path).unwrap();
            let u8arc = U8Arc::read(&data).unwrap();
            assert!(!u8arc.get_all_paths().is_empty());
        }
    }

    fn vec_with_data(len: usize) -> Vec<u8> {
        (0..len).map(|x| x as u8).collect()
    }

    fn check_data(v: &[u8]) -> bool {
        v.iter().enumerate().all(|(index, x)| *x == index as u8)
    }

    fn roundtrip(f: &U8Arc<'_>) -> U8Arc<'static> {
        U8Arc::read_vec(f.write_to_vec().unwrap()).unwrap()
    }

    #[test]
    fn test_new() {
        let mut u8arc = U8Arc::new();
        u8arc
            .add_entry_data("oarc/one.arc", vec_with_data(1))
            .unwrap();
        u8arc
            .add_entry_data("oarc/thirtytwo.arc", vec_with_data(32))
            .unwrap();
        u8arc
            .add_entry_data("dir/thirtythree.arc", vec_with_data(33))
            .unwrap();
        u8arc
            .add_entry_data("oarc/hundred.arc", vec_with_data(100))
            .unwrap();
        u8arc
            .add_entry_data("oarc/twohundred.arc", vec_with_data(200))
            .unwrap();
        let all_paths = [
            "/dir/thirtythree.arc",
            "/oarc/hundred.arc",
            "/oarc/one.arc",
            "/oarc/thirtytwo.arc",
            "/oarc/twohundred.arc",
        ];
        assert_eq!(u8arc.get_all_paths(), all_paths);
        let round = roundtrip(&u8arc);
        assert_eq!(round.get_all_paths(), all_paths);
        for path in round.get_all_paths() {
            assert!(check_data(round.get_entry_data(&path).unwrap()));
        }
    }
}
