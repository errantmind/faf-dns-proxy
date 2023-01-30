/*
FaF is a cutting edge, high performance dns proxy
Copyright (C) 2021  James Bates

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/// Attempt to set a higher process priority. -20 is the highest we can set on most distros.
#[inline]
pub fn set_maximum_process_priority() {
   faf_syscall::sys_call!(crate::const_sys::SYS_SETPRIORITY as isize, crate::const_sys::PRIO_PROCESS as isize, 0, -20);
}

/// Unshare the file descriptor table between threads to keep the fd number itself low, otherwise all
/// threads will share the same file descriptor table. A single file descriptor table is problematic if
/// we use file descriptors to index data structures
#[inline]
pub fn unshare_file_descriptors() {
   faf_syscall::sys_call!(crate::const_sys::SYS_UNSHARE as isize, crate::const_sys::CLONE_FILES as isize);
}

/// Uses xxhash to hash a byte slice
#[inline(always)]
pub fn hash64(bytes: &[u8]) -> u64 {
   use xxhash_rust::xxh3::xxh3_64;
   xxh3_64(bytes)
}

// Returns the checksum and the file size
#[inline(always)]
pub fn self_checksum() -> Option<(u64, usize)> {
   use std::io::Read;

   let current_exe = std::env::current_exe().unwrap();
   let mut f = std::fs::File::open(current_exe).ok()?;
   let file_len = f.metadata().ok()?.len();
   let mut bytes = Vec::with_capacity(file_len as usize + 1);
   f.read_to_end(&mut bytes).ok()?;
   Some((hash64(&bytes), bytes.len()))
}
