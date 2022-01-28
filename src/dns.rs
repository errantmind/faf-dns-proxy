enum Protocol {
   UDP,
   TCP,
}

#[inline]
pub fn get_id_big_endian(dns_buf_start: *const u8, len: usize) -> u16 {
   debug_assert!(len >= 2);
   unsafe { *(dns_buf_start as *const u16) }
}

#[inline]
pub fn set_id_big_endian(new_id: u16, dns_buf_start: *const u8, len: usize) {
   debug_assert!(len >= 2);
   unsafe { *(dns_buf_start as *mut u16) = new_id };
}

#[inline]
pub fn strip_tcp_dns_size_prefix(input: &Vec<u8>) -> &[u8] {
   &input[2..]
}

#[inline]
pub fn get_query_unique_id<'a>(dns_buf_start: *const u8, len: usize) -> &'a [u8] {
   // -> &[u8] {
   debug_assert!(len >= 19);
   unsafe {
      debug_assert_eq!(*dns_buf_start.add(4), 0u8);
      debug_assert_eq!(*dns_buf_start.add(5), 1u8);

      let dns_buf_end = dns_buf_start.add(len);

      let mut length = 0;
      let mut dns_qname_qtype_qclass_walker = dns_buf_start.add(12);
      while *dns_qname_qtype_qclass_walker != 0u8 && dns_qname_qtype_qclass_walker != dns_buf_end {
         length += 1;
         dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(1);
      }

      debug_assert!((dns_buf_end as usize - dns_qname_qtype_qclass_walker as usize) > 5);

      let query_slice =
         unsafe { core::slice::from_raw_parts_mut(dns_buf_start.add(12) as *mut u8, length as usize + 5) };
      println!("{:?}", query_slice);

      println!("length: {}", length);

      query_slice
   }
}
