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
      if *input_byte_walker == b'.' || input_byte_walker == in_buff_end {
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