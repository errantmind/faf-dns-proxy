/*
FaF is a high performance DNS over TLS proxy
Copyright (C) 2022  James Bates

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

// DNS packet structure reference: https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

#[inline]
pub fn get_id_network_byte_order(dns_buf_start: *const u8, len: usize) -> u16 {
   debug_assert!(len >= 2);
   unsafe { *(dns_buf_start as *const u16) }
}

#[inline]
pub fn set_id_network_byte_order(new_id: u16, input: &mut [u8]) {
   debug_assert!(input.len() >= 2);
   unsafe { *(input as *mut _ as *mut u16) = new_id };
}

#[inline]
pub fn get_tcp_dns_size_prefix_le(input: &[u8]) -> usize {
   debug_assert!(input.len() >= 2);
   let size_network_byte_order = unsafe { *(input as *const _ as *const u16) };
   u16::swap_bytes(size_network_byte_order) as usize
}

#[inline]
pub fn map_qtype_to_str(qtype: u16) -> &'static str {
   match qtype {
      1 => "A",
      2 => "NS",
      5 => "CNAME",
      6 => "SOA",
      12 => "PTR",
      15 => "MX",
      16 => "TXT",
      28 => "AAAA",
      33 => "SRV",
      41 => "OPT",
      43 => "DS",
      46 => "RRSIG",
      47 => "NSEC",
      48 => "DNSKEY",
      50 => "NSEC3",
      51 => "NSEC3PARAM",
      52 => "TLSA",
      59 => "CAA",
      99 => "SPF",
      250 => "TSIG",
      251 => "IXFR",
      252 => "AXFR",
      255 => "ANY",
      256 => "URI",
      257 => "CAA",
      32768 => "TA",
      32769 => "DLV",
      _ => "UNKNOWN",
   }
}

#[inline]
pub fn map_qclass_to_str(qclass: u16) -> &'static str {
   match qclass {
      1 => "IN",
      2 => "CS",
      3 => "CH",
      4 => "HS",
      255 => "ANY",
      _ => "UNKNOWN",
   }
}

/// Walks one question in the query (QNAME, QTYPE, QCLASS) and returns these bytes a slice of the buffer
#[inline]
pub fn get_query_unique_id<'a>(dns_buf_start: *const u8, len: usize) -> &'a [u8] {
   // The shortest query is for the root zone '.'. So Header (12 byets) + QNAME (3 bytes) + QTYPE (2 bytes) + QCLASS (2 bytes)
   const SHORTEST_POSSIBLE_QUESTION_BYTES: usize = 19;
   debug_assert!(len >= SHORTEST_POSSIBLE_QUESTION_BYTES);

   unsafe {
      // The number of questions is 2 bytes. We only support queries with a single question
      debug_assert!(*dns_buf_start.add(4) == 0u8, "More than one question per query is non-standard and unsupported");
      debug_assert!(*dns_buf_start.add(5) == 1u8, "More than one question per query is non-standard and unsupported");

      //println!("{}", get_question_as_string(dns_buf_start, len));

      // Skip the header
      let mut dns_qname_qtype_qclass_walker = dns_buf_start.add(12);

      const QNAME_TERMINATOR_QTYPE_QCLASS_LEN: usize = 5;
      let mut num_question_bytes: usize = 0;
      {
         const QNAME_TERMINATOR: u8 = 0;
         let dns_buf_end = dns_buf_start.add(len);
         while *dns_qname_qtype_qclass_walker != QNAME_TERMINATOR && dns_qname_qtype_qclass_walker != dns_buf_end {
            num_question_bytes += 1;
            dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(1);
         }

         debug_assert!((dns_buf_end as usize - dns_qname_qtype_qclass_walker as usize) >= QNAME_TERMINATOR_QTYPE_QCLASS_LEN);
      }

      core::slice::from_raw_parts(dns_buf_start.add(12), num_question_bytes + QNAME_TERMINATOR_QTYPE_QCLASS_LEN)
   }
}

#[inline]
pub fn get_question_as_string_and_lowest_ttl(dns_buf_start: *const u8, len: usize) -> (String, u64) {
   let mut question_str = String::new();
   let mut ttl: u32 = u32::MAX;
   unsafe {
      const QNAME_TERMINATOR: u8 = 0;
      let dns_buf_end = dns_buf_start.add(len);

      // Get the number of answers
      let mut dns_qname_qtype_qclass_walker = dns_buf_start.add(6);
      debug_assert!(dns_qname_qtype_qclass_walker.add(2) <= dns_buf_end);
      let num_answers = u16::swap_bytes(*(dns_qname_qtype_qclass_walker as *const _ as *const u16));

      // Skip the header
      dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(6);

      while *dns_qname_qtype_qclass_walker != QNAME_TERMINATOR && dns_qname_qtype_qclass_walker != dns_buf_end {
         let segment_len = *dns_qname_qtype_qclass_walker as usize;
         if !question_str.is_empty() {
            question_str.push('.');
         }
         question_str
            .push_str(std::str::from_utf8(core::slice::from_raw_parts(dns_qname_qtype_qclass_walker.add(1), segment_len)).unwrap());
         dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(1 + segment_len);
      }

      //// Skip Question section's QNAME TERMINATOR + QTYPE + QCLASS
      //dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(5);

      {
         // Include the entire query (.. + QTYPE + QCLASS)

         // Skip QNAME TERMINATOR
         dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(1);

         // Add separator between QNAME and QTYPE
         question_str.push(':');

         // Add QTYPE
         let qtype = u16::swap_bytes(*(dns_qname_qtype_qclass_walker as *const _ as *const u16));
         question_str.push_str(map_qtype_to_str(qtype));
         dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(2);

         // Add separator between QTYPE and QCLASS
         question_str.push(':');

         let qclass = u16::swap_bytes(*(dns_qname_qtype_qclass_walker as *const _ as *const u16));
         question_str.push_str(map_qclass_to_str(qclass));
         dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(2);
      }

      // Parse TTL from answers.
      // This is where it gets tricky due to the compression scheme used. It can use pointers (offsets) but doesn't have to.
      // We will also be tricky to do the minimum amout of parsing.
      // To grok, please refer to the reference mentioned towards the top of this file.

      for i in 0..num_answers {
         if i > 0 {
            // If there is only a single answer, we don't want to do the work of getting to the next TTL.
            // Similarly, if this is the last answer, we don't want to do redundant work for getting to the next entry.
            // So, by putting this logic first, we avoid both.

            // Skips past the previous TTL
            dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(4);

            // Skips RDATA section
            let size_be = *(dns_qname_qtype_qclass_walker as *const _ as *const u16);
            let rdlength = u16::swap_bytes(size_be);
            dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(2 + rdlength as usize);
         }

         let first_byte = *dns_qname_qtype_qclass_walker;
         if first_byte >= 192 {
            // A pointer has been specified so skip the 2 byte section (pointer specified and offset), the TYPE and CLASS
            dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(6);
         } else {
            // I've noticed this is hit for 'cdn.fluidpreview.office.net'
            println!(
               "          {} parse malfunction. DNS may be misconfigured for this domain. TTL could not be determined, using {}s",
               question_str, 500
            );

            return (question_str, 500);
         }

         let size_be = *(dns_qname_qtype_qclass_walker as *const _ as *const u32);
         let latest_ttl = u32::swap_bytes(size_be);
         if latest_ttl < ttl {
            ttl = latest_ttl;
         }
      }
   }

   (question_str, ttl as u64)
}
