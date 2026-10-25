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
pub const MAX_DNS_MESSAGE_SIZE: usize = 1_232;

/// Represents the result of processing a DNS response
pub struct DnsResponseResult {
   pub site_name: String,
   pub qtype_str: &'static str,
   pub qclass_str: &'static str,
   pub ttl: u64,
   pub elapsed_ms: u128,
}

/// Processes a DNS response and extracts all necessary information for caching and logging
pub fn process_dns_response(question: &ParsedQuestion<'_>, asked_at_opt: Option<u128>) -> DnsResponseResult {
   let elapsed_ms = match asked_at_opt {
      Some(asked_at) => crate::util::get_unix_ts_millis() - asked_at,
      None => 0,
   };

   let (site_name, qtype_str, qclass_str, mut ttl) = get_question_as_string_and_lowest_ttl(question);
   // Apply minimum TTL override
   if ttl < crate::statics::MINIMUM_TTL_OVERRIDE {
      ttl = crate::statics::MINIMUM_TTL_OVERRIDE;
   }

   DnsResponseResult { site_name, qtype_str, qclass_str, ttl, elapsed_ms }
}

/// Creates a cache entry from a processed DNS response.
pub fn create_cache_entry_from_response(
   response_result: &DnsResponseResult,
   udp_segment: &[u8],
   refresh_generation: u64,
   previous_expires_at: Option<tokio::time::Instant>,
   refresh_lease_until_ms: u64,
) -> crate::cache::AnswerCacheEntry {
   crate::cache::AnswerCacheEntry {
      answer: udp_segment.to_vec(),
      elapsed_ms: response_result.elapsed_ms,
      expires_at: tokio::time::Instant::now() + std::time::Duration::from_secs(response_result.ttl),
      previous_expires_at,
      refresh_generation,
      refresh_state: std::sync::atomic::AtomicU8::new(0),
      refresh_lease_until_ms: std::sync::atomic::AtomicU64::new(refresh_lease_until_ms),
   }
}

/// Converts the saved question prefix of a DNS response into a reusable query.
#[inline]
pub fn create_refresh_query(response: &[u8], question_len: usize) -> Option<Vec<u8>> {
   let query_len = 12usize.checked_add(question_len)?;
   let mut query = response.get(..query_len)?.to_vec();

   // Keep RD/CD from the original request semantics represented in the response,
   // clear response-only flags/RCODE, and restore a one-question query header.
   query[2] &= 0b0000_0001;
   query[3] &= 0b0001_0000;
   query[4..6].copy_from_slice(&1u16.to_be_bytes());
   query[6..12].fill(0);
   Some(query)
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
pub fn set_id_network_byte_order(new_id: u16, input: &mut [u8]) {
   input[..2].copy_from_slice(&new_id.to_ne_bytes());
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
      32_768 => "TA",
      32_769 => "DLV",
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

pub struct ParsedQuestion<'a> {
   message: &'a [u8],
   question_end: usize,
}

impl<'a> ParsedQuestion<'a> {
   #[inline]
   pub fn parse(message: &'a [u8]) -> Option<Self> {
      if message.len() < 17 || message[4..6] != [0, 1] {
         return None;
      }

      let prefix = &message[..(message.len() - 4).min(12 + 255)];
      let mut offset = 12;
      loop {
         let &length = prefix.get(offset)?;
         if length == 0 {
            return Some(Self { message, question_end: offset + 5 });
         }
         if length > 63 {
            return None;
         }
         offset += usize::from(length) + 1;
      }
   }

   #[inline]
   pub fn parse_response(message: &'a [u8]) -> Option<Self> {
      let question = Self::parse(message)?;
      if message[2] & 0b1000_0000 == 0 || !matches!(message[3] & 0b0000_1111, 0 | 3) {
         return None;
      }
      Some(question)
   }

   #[inline]
   pub fn id(&self) -> u16 {
      u16::from_ne_bytes(*self.message.first_chunk::<2>().unwrap())
   }

   #[inline]
   pub fn cache_key(&self) -> &'a [u8] {
      &self.message[12..][..self.question_end - 12]
   }

   #[inline]
   pub fn message(&self) -> &'a [u8] {
      self.message
   }
}

const TTL_PARSE_FALLBACK_SECS: u64 = 10;

/// Returns the first byte after an encoded DNS name without decompressing it.
///
/// A name can be a sequence of labels terminated by zero, a two-byte
/// compression pointer, or labels followed by a compression pointer.
#[inline]
fn skip_dns_name(message: &[u8], mut offset: usize) -> Option<usize> {
   loop {
      let first_byte = *message.get(offset)?;
      match first_byte & 0b1100_0000 {
         0b1100_0000 => {
            let second_byte = *message.get(offset.checked_add(1)?)?;
            let pointer_offset = (((first_byte & 0b0011_1111) as usize) << 8) | second_byte as usize;
            if pointer_offset >= message.len() {
               return None;
            }
            return offset.checked_add(2);
         }
         0 => {
            offset = offset.checked_add(1)?;
            if first_byte == 0 {
               return Some(offset);
            }
            offset = offset.checked_add(first_byte as usize)?;
            if offset > message.len() {
               return None;
            }
         }
         // Label prefixes 01 and 10 are reserved.
         _ => return None,
      }
   }
}

#[cold]
fn ttl_parse_fallback(question: String, qtype: u16, qclass: u16) -> (String, &'static str, &'static str, u64) {
   eprintln!("          Could not parse answer TTL for {question}; using {TTL_PARSE_FALLBACK_SECS}s");
   (question, map_qtype_to_str(qtype), map_qclass_to_str(qclass), TTL_PARSE_FALLBACK_SECS)
}

#[cold]
fn append_escaped_label(output: &mut String, label: &[u8]) {
   use std::fmt::Write;

   for &byte in label {
      if (b' '..=b'~').contains(&byte) && !matches!(byte, b'.' | b'\\') {
         output.push(char::from(byte));
      } else {
         write!(output, "\\{byte:03}").unwrap();
      }
   }
}

#[inline]
pub fn get_question_as_string_and_lowest_ttl(question: &ParsedQuestion<'_>) -> (String, &'static str, &'static str, u64) {
   let dns_message = question.message;
   let mut name = &dns_message[12..question.question_end - 5];
   let mut question_str = String::with_capacity(name.len());
   while let Some((&length, tail)) = name.split_first() {
      let (label, rest) = tail.split_at(usize::from(length));
      if !question_str.is_empty() {
         question_str.push('.');
      }
      if let Ok(text) = std::str::from_utf8(label)
         && !text.chars().any(|character| character.is_control() || matches!(character, '.' | '\\'))
      {
         question_str.push_str(text);
      } else {
         append_escaped_label(&mut question_str, label);
      }
      name = rest;
   }

   let num_answers = u16::from_be_bytes([dns_message[6], dns_message[7]]);
   let question_fields = &dns_message[question.question_end - 4..question.question_end];
   let qtype = u16::from_be_bytes([question_fields[0], question_fields[1]]);
   let qclass = u16::from_be_bytes([question_fields[2], question_fields[3]]);

   if num_answers == 0 {
      return (question_str, map_qtype_to_str(qtype), map_qclass_to_str(qclass), 0);
   }

   let mut answer_offset = question.question_end;
   let mut ttl = u32::MAX;

   for _ in 0..num_answers {
      let Some(fixed_fields_offset) = skip_dns_name(dns_message, answer_offset) else {
         return ttl_parse_fallback(question_str, qtype, qclass);
      };
      let Some(fixed_fields_end) = fixed_fields_offset.checked_add(10) else {
         return ttl_parse_fallback(question_str, qtype, qclass);
      };
      let Some(fixed_fields) = dns_message.get(fixed_fields_offset..fixed_fields_end) else {
         return ttl_parse_fallback(question_str, qtype, qclass);
      };

      let latest_ttl = u32::from_be_bytes(fixed_fields[4..8].try_into().unwrap());
      ttl = ttl.min(latest_ttl);

      let rdlength = u16::from_be_bytes(fixed_fields[8..10].try_into().unwrap()) as usize;
      let Some(next_answer_offset) = fixed_fields_end.checked_add(rdlength) else {
         return ttl_parse_fallback(question_str, qtype, qclass);
      };
      if next_answer_offset > dns_message.len() {
         return ttl_parse_fallback(question_str, qtype, qclass);
      }
      answer_offset = next_answer_offset;
   }

   (question_str, map_qtype_to_str(qtype), map_qclass_to_str(qclass), ttl as u64)
}
