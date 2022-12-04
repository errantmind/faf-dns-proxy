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

use crate::const_sys::*;
use faf_syscall::sys_call;

const DOT: u8 = b'.';

#[derive(Debug)]
#[repr(C)]
pub struct rlimit {
   pub rlim_cur: u32, /* Soft limit */
   pub rlim_max: u32, /* Hard limit */
}

const _SC_NPROCESSORS_ONLN: i32 = 84;

extern "C" {
   fn sysconf(name: i32) -> isize;

   fn sched_getaffinity(pid: i32, cpusetsize: usize, cpuset: *mut cpu_set_t) -> i32;
   fn sched_setaffinity(pid: i32, cpusetsize: usize, cpuset: *const cpu_set_t) -> i32;
}

const POINTER_WIDTH_IN_BITS: usize = core::mem::size_of::<usize>() * 8;

// We always want a total of 1024 bits, so 16 segments on 64-bit platforms, 32 segments on 32-bit platforms
const CPU_SET_LEN: usize = 1024 / POINTER_WIDTH_IN_BITS;

#[repr(C, align(64))]
struct cpu_set_t([usize; CPU_SET_LEN]);

#[inline]
fn cpu_isset(cpu_num: usize, set: &cpu_set_t) -> bool {
   let chunk_index = cpu_num / POINTER_WIDTH_IN_BITS;
   let chunk_offset = cpu_num % POINTER_WIDTH_IN_BITS;
   ((1 << chunk_offset) & set.0[chunk_index]) != 0
}

#[inline]
fn cpu_set(cpu_num: usize, set: &mut cpu_set_t) {
   let chunk_index = cpu_num / POINTER_WIDTH_IN_BITS;
   let chunk_offset = cpu_num % POINTER_WIDTH_IN_BITS;
   set.0[chunk_index] |= 1 << chunk_offset;
}

// 0 indicates the current thread's PID for this API
const CURRENT_THREAD_CONTROL_PID: i32 = 0;

#[inline]
pub fn set_current_thread_cpu_affinity_to(cpu_num: usize) {
   let mut set: cpu_set_t = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
   unsafe {
      sched_getaffinity(CURRENT_THREAD_CONTROL_PID, core::mem::size_of::<cpu_set_t>(), &mut set);
   }
   if !cpu_isset(cpu_num, &set) {
      eprintln!("Cannot set affinity for cpu {}", cpu_num);
   } else {
      let mut set_control: cpu_set_t = unsafe { core::mem::MaybeUninit::zeroed().assume_init() };
      cpu_set(cpu_num, &mut set_control);
      unsafe {
         sched_setaffinity(0, core::mem::size_of::<cpu_set_t>(), &set_control);
      }
   }
}

#[inline]
pub fn get_num_logical_cpus() -> usize {
   let cpus = unsafe { sysconf(_SC_NPROCESSORS_ONLN) };
   if cpus <= 0 {
      eprintln!("Cannot determine the number of logical cpus with sysconf, performance will be severely impacted");
      1
   } else {
      cpus as usize
   }
}


/// Attempt to set a higher process priority. -20 is the highest we can set on most distros.
#[inline]
pub fn set_maximum_process_priority() {
   sys_call!(SYS_SETPRIORITY as isize, PRIO_PROCESS as isize, 0, -20);
}

/// Unshare the file descriptor table between threads to keep the fd number itself low, otherwise all
/// threads will share the same file descriptor table. A single file descriptor table is problematic if
/// we use file descriptors to index data structures
#[inline]
pub fn unshare_file_descriptors() {
   sys_call!(SYS_UNSHARE as isize, CLONE_FILES as isize);
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

/// Converts str of an IP address representing an internet host to a 32-bit int which represents
/// also represents the same IP address which is in network byte order
///
/// A maximum of 15 bytes (XXX.XXX.XXX.XXX) are read from the input buffer which is enough to represent any
/// valid IPV4 address from 0.0.0.0 to 255.255.255.255
///
/// Example:
///
/// ```
/// use faf::util::inet4_aton;
///
/// unsafe {
///    const IP: &str = "127.0.0.1";
///    let ip_buff_ptr = IP as *const _ as *const u8;
///    let ip_host_int: u32 = inet4_aton(ip_buff_ptr, IP.len());
///    assert_eq!(ip_host_int, 16777343);
/// }
/// ```

#[inline]
pub unsafe fn inet4_aton(in_buff_start: *const u8, len: usize) -> u32 {
   let s_addr: u32 = 0;
   let mut s_addr_ptr = &s_addr as *const _ as *mut u8;
   let mut output: u8 = 0;
   let in_buff_end = in_buff_start.add(len);
   let mut input_byte_walker = in_buff_start;

   loop {
      if *input_byte_walker == DOT || input_byte_walker == in_buff_end {
         *s_addr_ptr = output;
         s_addr_ptr = s_addr_ptr.add(1);
         output = 0;
         if input_byte_walker == in_buff_end {
            break;
         }
      } else {
         output = output * 10 + (*input_byte_walker - 48u8);
      }

      input_byte_walker = input_byte_walker.add(1);
   }

   s_addr
}

#[test]
#[inline]
fn test_inet4_aton() {
   unsafe {
      const TEST1: &str = "127.0.0.1";
      let ip_buff_ptr = TEST1 as *const _ as *const u8;
      let res = inet4_aton(ip_buff_ptr, TEST1.len());
      assert_eq!(res, 16777343);
      println!("{}", res);

      const TEST2: &str = "192.168.0.189";
      let ip_buff_ptr = TEST2 as *const _ as *const u8;
      let res = inet4_aton(ip_buff_ptr, TEST2.len());
      assert_eq!(res, 3170937024);
      println!("{}", res);
   }
}
