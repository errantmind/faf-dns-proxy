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

/// Maximum DNS message size supported by the proxy.
///
/// 1232 bytes accommodates most modern DNS responses while generally avoiding
/// IP fragmentation. Avoids common DNSSEC timeouts. Larger DNS-over-TCP/TLS
/// responses are consumed and skipped.
pub const MAX_DNS_MESSAGE_SIZE: usize = 1232;

/// Represents the result of processing a DNS response
pub struct DnsResponseResult {
   pub site_name: String,
   pub qtype_str: &'static str,
   pub qclass_str: &'static str,
   pub ttl: u64,
   pub elapsed_ms: u128,
}

/// Processes a DNS response and extracts all necessary information for caching and logging
pub fn process_dns_response(udp_segment: &[u8], asked_at_opt: Option<u128>) -> DnsResponseResult {
   let elapsed_ms = match asked_at_opt {
      Some(asked_at) => crate::util::get_unix_ts_millis() - asked_at,
      None => 0,
   };

   let (site_name, qtype_str, qclass_str, mut ttl) = get_question_as_string_and_lowest_ttl(udp_segment.as_ptr(), udp_segment.len());
   // Apply minimum TTL override
   if ttl < crate::statics::MINIMUM_TTL_OVERRIDE {
      ttl = crate::statics::MINIMUM_TTL_OVERRIDE;
   }

   DnsResponseResult { site_name, qtype_str, qclass_str, ttl, elapsed_ms }
}

/// Creates a cache entry from a processed DNS response
pub fn create_cache_entry_from_response(response_result: &DnsResponseResult, udp_segment: &[u8]) -> crate::cache::AnswerCacheEntry {
   crate::cache::AnswerCacheEntry {
      answer: udp_segment.to_vec(),
      elapsed_ms: response_result.elapsed_ms,
      expires_at: crate::util::get_unix_ts_secs() + response_result.ttl,
   }
}

#[inline]
pub fn create_servfail_response(dns_buf: &mut [u8]) -> Option<()> {
   if dns_buf.len() < 12 {
      return None;
   }

   // Set QR and RA, clear answer/authority/additional counts, and set RCODE to SERVFAIL.
   dns_buf[2] |= 0b1000_0000;
   dns_buf[3] = (dns_buf[3] & 0b0001_0000) | 0b1000_0010;
   dns_buf[6..12].fill(0);

   Some(())
}

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
pub fn get_tcp_dns_size_prefix(input: &[u8; 2]) -> usize {
   u16::from_be_bytes(*input) as usize
}

#[inline]
pub fn map_qtype_to_str(qtype: u16) -> &'static str {
   match qtype {
      1 => "A",
      2 => "NS",
      5 => "CNAME",
      6 => "SOA",
      12 => "PTR",
      13 => "HINFO",
      15 => "MX",
      16 => "TXT",
      17 => "RP",
      18 => "AFSDB",
      24 => "SIG",
      25 => "KEY",
      28 => "AAAA",
      29 => "LOC",
      33 => "SRV",
      35 => "NAPTR",
      36 => "KX",
      37 => "CERT",
      39 => "DNAME",
      41 => "OPT",
      42 => "APL",
      43 => "DS",
      44 => "SSHFP",
      45 => "IPSECKEY",
      46 => "RRSIG",
      47 => "NSEC",
      48 => "DNSKEY",
      49 => "DHCID",
      50 => "NSEC3",
      51 => "NSEC3PARAM",
      52 => "TLSA",
      53 => "SMIMEA",
      55 => "HIP",
      56 => "NINFO",
      57 => "RKEY",
      58 => "TALINK",
      59 => "CDS",
      60 => "CDNSKEY",
      61 => "OPENPGPKEY",
      62 => "CSYNC",
      63 => "ZONEMD",
      64 => "SVCB",
      65 => "HTTPS",
      99 => "SPF",
      108 => "EUI48",
      109 => "EUI64",
      249 => "TKEY",
      250 => "TSIG",
      251 => "IXFR",
      252 => "AXFR",
      253 => "MAILB",
      254 => "MAILA",
      255 => "ANY",
      256 => "URI",
      257 => "CAA",
      258 => "AVC",
      259 => "DOA",
      260 => "AMTRELAY",
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
pub fn get_question_as_string(dns_buf_start: *const u8, len: usize) -> String {
   let mut question_str = String::new();
   unsafe {
      const QNAME_TERMINATOR: u8 = 0;
      let dns_buf_end = dns_buf_start.add(len);

      // Skip the header
      let mut dns_qname_qtype_qclass_walker = dns_buf_start.add(12);

      while *dns_qname_qtype_qclass_walker != QNAME_TERMINATOR && dns_qname_qtype_qclass_walker != dns_buf_end {
         let segment_len = *dns_qname_qtype_qclass_walker as usize;
         if !question_str.is_empty() {
            question_str.push('.');
         }
         question_str
            .push_str(std::str::from_utf8(core::slice::from_raw_parts(dns_qname_qtype_qclass_walker.add(1), segment_len)).unwrap());
         dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(1 + segment_len);
      }

      question_str
   }
}

#[inline]
pub fn get_question_as_string_and_lowest_ttl(dns_buf_start: *const u8, len: usize) -> (String, &'static str, &'static str, u64) {
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

      // Include the entire query (.. + QTYPE + QCLASS)

      // Skip QNAME TERMINATOR
      dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(1);

      // Add QTYPE
      let qtype = u16::swap_bytes(*(dns_qname_qtype_qclass_walker as *const _ as *const u16));
      dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(2);

      // Add QCLASS
      let qclass = u16::swap_bytes(*(dns_qname_qtype_qclass_walker as *const _ as *const u16));
      dns_qname_qtype_qclass_walker = dns_qname_qtype_qclass_walker.add(2);

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
               question_str, 10
            );

            return (question_str, map_qtype_to_str(qtype), map_qclass_to_str(qclass), 10);
         }

         let size_be = *(dns_qname_qtype_qclass_walker as *const _ as *const u32);
         let latest_ttl = u32::swap_bytes(size_be);
         if latest_ttl < ttl {
            ttl = latest_ttl;
         }
      }

      // If no answers were processed (NXDOMAIN/NODATA), set TTL to 0
      if num_answers == 0 {
         ttl = 0;
      }

      (question_str, map_qtype_to_str(qtype), map_qclass_to_str(qclass), ttl as u64)
   }
}

/// Extract the qtype from a DNS query packet
#[inline]
pub fn get_qtype_from_query(dns_buf_start: *const u8, len: usize) -> u16 {
   unsafe {
      const QNAME_TERMINATOR: u8 = 0;
      let dns_buf_end = dns_buf_start.add(len);
      // Skip the header (12 bytes)
      let mut dns_qname_walker = dns_buf_start.add(12);

      // Walk through the QNAME to find the terminator
      while *dns_qname_walker != QNAME_TERMINATOR && dns_qname_walker < dns_buf_end {
         dns_qname_walker = dns_qname_walker.add(1);
      }

      // Skip the QNAME terminator (1 byte) to get to QTYPE
      dns_qname_walker = dns_qname_walker.add(1);

      // Read QTYPE (2 bytes in network byte order)
      if dns_qname_walker.add(2) <= dns_buf_end {
         u16::swap_bytes(*(dns_qname_walker as *const u16))
      } else {
         0 // Return 0 if we can't read the qtype safely
      }
   }
}

#[inline]
pub fn check_for_usable_response(dns_buf: &[u8]) -> Option<bool> {
   if dns_buf.len() < 17 || dns_buf[2] & 0b1000_0000 == 0 || dns_buf[4..6] != [0, 1] {
      return None;
   }

   let mut qname_offset = 12;
   loop {
      let label_len = *dns_buf.get(qname_offset)? as usize;
      if label_len == 0 {
         if qname_offset + 5 > dns_buf.len() {
            return None;
         }
         break;
      }
      if label_len > 63 || qname_offset + label_len + 1 >= dns_buf.len() {
         return None;
      }
      qname_offset += label_len + 1;
   }

   Some(matches!(dns_buf[3] & 0b0000_1111, 0 | 3))
}

#[test]
fn create_servfail_response_test() {
   let mut query = [0u8; 19];
   query[2] = 0b0000_0001;
   query[3] = 0b0001_1111;
   query[5] = 1;
   query[7] = 2;
   query[9] = 3;
   query[11] = 4;

   create_servfail_response(&mut query);

   assert_eq!(query[2], 0b1000_0001);
   assert_eq!(query[3], 0b1001_0010);
   assert_eq!(&query[4..12], &[0, 1, 0, 0, 0, 0, 0, 0]);
}
