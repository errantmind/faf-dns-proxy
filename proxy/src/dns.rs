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
   pub cache_layout: Option<ResponseCacheLayout>,
}

#[derive(Clone, Copy)]
pub struct ResponseCacheLayout {
   pub opt_offset: Option<u16>,
}

/// Processes a DNS response and extracts all necessary information for caching and logging
pub fn process_dns_response(
   question: &ParsedQuestion<'_>,
   asked_at_opt: Option<u128>,
   settings: Option<QuerySettings>,
) -> DnsResponseResult {
   let elapsed_ms = match asked_at_opt {
      Some(asked_at) => crate::util::get_unix_ts_millis() - asked_at,
      None => 0,
   };

   let mut result = get_question_as_string_and_lowest_ttl(question, settings);
   // Apply minimum TTL override
   if result.ttl < crate::statics::MINIMUM_TTL_OVERRIDE {
      result.ttl = crate::statics::MINIMUM_TTL_OVERRIDE;
   }
   result.elapsed_ms = elapsed_ms;
   result
}

/// Creates a cache entry from a processed DNS response.
pub fn create_cache_entry_from_response(
   response_result: &DnsResponseResult,
   udp_segment: &[u8],
   refresh_generation: u64,
   previous_expires_at: Option<tokio::time::Instant>,
   refresh_lease_until_ms: u64,
) -> crate::cache::AnswerCacheEntry {
   let opt_offset = response_result.cache_layout.and_then(|layout| layout.opt_offset);
   let mut answer = udp_segment.to_vec();
   if let Some(offset) = opt_offset {
      answer[usize::from(offset)..usize::from(offset) + 11].fill(0);
   }
   crate::cache::AnswerCacheEntry {
      answer,
      opt_offset,
      elapsed_ms: response_result.elapsed_ms,
      expires_at: tokio::time::Instant::now() + std::time::Duration::from_secs(response_result.ttl),
      previous_expires_at,
      refresh_generation,
      refresh_state: std::sync::atomic::AtomicU8::new(0),
      refresh_lease_until_ms: std::sync::atomic::AtomicU64::new(refresh_lease_until_ms),
   }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuerySettings(u64);

impl QuerySettings {
   #[inline]
   pub fn opt_len(self) -> usize {
      if self.0 & (1 << 32) != 0 { 11 } else { 0 }
   }

   #[inline]
   fn udp_payload(self) -> u16 {
      if self.opt_len() == 0 { 512 } else { ((self.0 >> 16) as u16).max(512) }
   }

   #[inline]
   fn opt(self, payload: u16) -> [u8; 11] {
      let size = payload.to_be_bytes();
      [0, 0, 41, size[0], size[1], 0, 0, if self.0 & (1 << 33) != 0 { 0x80 } else { 0 }, 0, 0, 0]
   }

   #[inline]
   pub fn write_response_opt(self, output: &mut [u8]) {
      output.copy_from_slice(&self.opt(MAX_DNS_MESSAGE_SIZE as u16));
   }
}

#[inline]
pub fn create_refresh_query(question: &[u8], settings: QuerySettings, upstream_id: u16) -> Vec<u8> {
   let mut query = Vec::with_capacity(12 + question.len() + settings.opt_len());
   query.extend_from_slice(&upstream_id.to_ne_bytes());
   query.extend_from_slice(&(settings.0 as u16).to_be_bytes());
   query.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(settings.opt_len() != 0)]);
   query.extend_from_slice(question);
   if settings.opt_len() != 0 {
      query.extend_from_slice(&settings.opt((settings.0 >> 16) as u16));
   }
   query
}

#[inline]
pub fn create_servfail_response(dns_buf: &mut [u8], question_len: usize, settings: Option<QuerySettings>) -> Option<usize> {
   let question_end = 12usize.checked_add(question_len)?;
   let response_len = question_end.checked_add(settings.map_or(0, QuerySettings::opt_len))?;
   let response = dns_buf.get_mut(..response_len)?;
   if question_len < 5 {
      return None;
   }

   response[2] = (response[2] & 0b0111_1001) | 0b1000_0000;
   response[3] = (response[3] & 0b0001_0000) | 0b1000_0010;
   response[6..12].fill(0);
   if let Some(settings) = settings
      && settings.opt_len() != 0
   {
      response[11] = 1;
      settings.write_response_opt(&mut response[question_end..]);
   }
   Some(response_len)
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

   #[inline]
   pub fn settings(&self) -> Option<QuerySettings> {
      let message = self.message;
      let flags = u16::from_be_bytes([message[2], message[3]]);
      if flags & !0x0130 != 0 || message[6..10] != [0; 4] {
         return None;
      }
      let qtype = u16::from_be_bytes([message[self.question_end - 4], message[self.question_end - 3]]);
      if matches!(qtype, 249..=252) {
         return None;
      }
      if message[10..12] == [0, 0] && self.question_end == message.len() {
         return Some(QuerySettings(u64::from(flags)));
      }
      let opt = &message[self.question_end..];
      if message[10..12] != [0, 1]
         || opt.len() != 11
         || opt[..3] != [0, 0, 41]
         || u32::from_be_bytes(opt[5..9].try_into().unwrap()) & !0x8000 != 0
         || opt[9..11] != [0, 0]
      {
         return None;
      }
      let payload = u16::from_be_bytes([opt[3], opt[4]]);
      Some(QuerySettings(u64::from(flags) | (u64::from(payload) << 16) | (1 << 32) | (u64::from(opt[7] >> 7) << 33)))
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
fn ttl_parse_fallback(mut response: DnsResponseResult) -> DnsResponseResult {
   eprintln!("          Could not parse answer TTL for {}; using {TTL_PARSE_FALLBACK_SECS}s", response.site_name);
   response.ttl = TTL_PARSE_FALLBACK_SECS;
   response.cache_layout = None;
   response
}

#[inline]
fn record_fields(message: &[u8], offset: usize) -> Option<(usize, &[u8], usize)> {
   let fixed_offset = skip_dns_name(message, offset)?;
   let fixed_end = fixed_offset.checked_add(10)?;
   let fields = message.get(fixed_offset..fixed_end)?;
   let rdlength = usize::from(u16::from_be_bytes(fields[8..10].try_into().unwrap()));
   let next_offset = fixed_end.checked_add(rdlength)?;
   (next_offset <= message.len()).then_some((fixed_offset, fields, next_offset))
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
pub fn get_question_as_string_and_lowest_ttl(question: &ParsedQuestion<'_>, settings: Option<QuerySettings>) -> DnsResponseResult {
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

   let mut result = DnsResponseResult {
      site_name: question_str,
      qtype_str: map_qtype_to_str(qtype),
      qclass_str: map_qclass_to_str(qclass),
      ttl: 0,
      elapsed_ms: 0,
      cache_layout: None,
   };
   let mut cacheable = settings.is_some_and(|settings| dns_message.len() <= usize::from(settings.udp_payload()))
      && dns_message.len() <= MAX_DNS_MESSAGE_SIZE
      && dns_message[2] & 0b0111_1010 == 0;
   let counts = [
      num_answers,
      if cacheable { u16::from_be_bytes([dns_message[8], dns_message[9]]) } else { 0 },
      if cacheable { u16::from_be_bytes([dns_message[10], dns_message[11]]) } else { 0 },
   ];
   let mut offset = question.question_end;
   let mut ttl = u32::MAX;
   let mut opt_offset = None;

   for (section, count) in counts.into_iter().enumerate() {
      for _ in 0..count {
         let Some((fixed_offset, fields, next_offset)) = record_fields(dns_message, offset) else {
            return if section == 0 { ttl_parse_fallback(result) } else { result };
         };
         if section == 0 {
            ttl = ttl.min(u32::from_be_bytes(fields[4..8].try_into().unwrap()));
         }
         if cacheable {
            let kind = u16::from_be_bytes([fields[0], fields[1]]);
            if kind == 41 {
               if section != 2
                  || opt_offset.is_some()
                  || fixed_offset != offset + 1
                  || dns_message[offset] != 0
                  || fields[8..10] != [0, 0]
                  || u32::from_be_bytes(fields[4..8].try_into().unwrap()) & !0x8000 != 0
               {
                  cacheable = false;
               }
               opt_offset = Some(offset as u16);
            } else if kind == 250 || (kind == 24 && section == 2) {
               cacheable = false;
            }
         }
         offset = next_offset;
      }
      if section == 0 && num_answers > 0 {
         result.ttl = u64::from(ttl);
      }
      if !cacheable {
         return result;
      }
   }

   if offset == dns_message.len() && opt_offset.is_some() == settings.is_some_and(|settings| settings.opt_len() != 0) {
      result.cache_layout = Some(ResponseCacheLayout { opt_offset });
   }
   result
}
