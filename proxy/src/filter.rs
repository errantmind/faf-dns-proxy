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

//! Domain filtering module for DNS queries
//!
//! This module provides a unified interface for domain filtering functionality,
//! including blocklist management, domain extraction, and response generation.

use tokio::net::UdpSocket;

lazy_static::lazy_static! {
   /// Stores lists of blocked domains loaded from blocklists
   static ref BLOCKLISTS: tokio::sync::Mutex<Vec<crate::blocklist::BlocklistFile>> = tokio::sync::Mutex::new(Vec::new());
}

/// Result of domain filtering operation
pub struct FilterResult {
   pub is_blocked: bool,
   pub question: String,
   pub primary_domain: String,
}

/// Initialize the domain filtering system
pub async fn initialize_blocklists() {
   if crate::statics::ARGS.blocklists {
      let blocklist = crate::blocklist::get_blocklists().await;
      *BLOCKLISTS.lock().await = blocklist;
   }
}

/// Extract domain information from DNS query for filtering
pub fn extract_domain_info(udp_segment: &[u8]) -> (String, String) {
   let question = crate::dns::get_question_as_string(udp_segment.as_ptr(), udp_segment.len());

   // Extract primary domain for blocklist matching
   // The blocklists are not accurate because they are derived from the browser regex filters. They exclude most subdomains.
   let mut primary_domain = String::new();
   let parts: Vec<&str> = question.rsplitn(3, '.').collect();
   if parts.len() > 2 {
      primary_domain = format!("{}.{}", parts[1], parts[0]);
   }

   (question, primary_domain)
}

/// Check if a query is for IPv6 (AAAA record)
#[inline]
fn is_ipv6_query(udp_segment: &[u8]) -> bool {
   const AAAA_QTYPE: u16 = 28;
   let qtype = crate::dns::get_qtype_from_query(udp_segment.as_ptr(), udp_segment.len());
   qtype == AAAA_QTYPE
}

/// Check if a domain is blocked and handle the response
pub async fn process_domain_filtering(
   udp_segment: &mut [u8],
   listener_socket: &UdpSocket,
   client_addr: &std::net::SocketAddr,
) -> FilterResult {
   let (question, primary_domain) = extract_domain_info(udp_segment);

   // Check IPv6 blocking first (independent of blocklists)
   if crate::statics::ARGS.disable_ipv6 && is_ipv6_query(udp_segment) {
      // Convert query to blocked response (NXDOMAIN)
      create_blocked_response(udp_segment);

      // Send blocked response to client
      let wrote_len_maybe = listener_socket.send_to(udp_segment, client_addr).await;

      if let Ok(wrote_len) = wrote_len_maybe {
         if wrote_len == 0 {
            eprintln!("Failed to write IPv6 blocked response to the client. 0 bytes written at {}:{}", file!(), line!());
         }
      } else {
         eprintln!(
            "Failed to write IPv6 blocked response to the client with error: {} at {}:{}",
            wrote_len_maybe.unwrap_err(),
            file!(),
            line!()
         );
      }

      return FilterResult { is_blocked: true, question, primary_domain };
   }

   // Check domain blocklists (only if --blocklists is enabled)
   if !crate::statics::ARGS.blocklists {
      return FilterResult { is_blocked: false, question, primary_domain };
   }

   // Check if domain is blocked
   let mut domain_is_blocked = false;
   for blocklist_file in BLOCKLISTS.lock().await.iter() {
      if blocklist_file.blocked_domains.contains(&question)
         || (!primary_domain.is_empty() && blocklist_file.blocked_domains.contains(&primary_domain))
      {
         // Convert query to blocked response
         create_blocked_response(udp_segment);

         // Send blocked response to client
         let wrote_len_maybe = listener_socket.send_to(udp_segment, client_addr).await;

         if let Ok(wrote_len) = wrote_len_maybe {
            // Due to how rust implements IO for send_to, we will never have a len_written less than 0
            if wrote_len == 0 {
               eprintln!("Failed to write blocked response to the client. 0 bytes written at {}:{}", file!(), line!());
            }
         } else {
            eprintln!(
               "Failed to write blocked response to the client with error: {} at {}:{}",
               wrote_len_maybe.unwrap_err(),
               file!(),
               line!()
            );
         }

         domain_is_blocked = true;
         break;
      }
   }

   FilterResult { is_blocked: domain_is_blocked, question, primary_domain }
}

/// Create a blocked response (NXDOMAIN) from a DNS query
#[inline]
pub fn create_blocked_response(dns_buf: &mut [u8]) -> Option<()> {
   if dns_buf.len() < 4 {
      return None;
   }

   // Set the QR bit to 1 (response)
   dns_buf[2] |= 0b1000_0000;

   // Set the RA bit to 1 (recursion available)
   dns_buf[3] |= 0b1000_0000;

   // Set the RCODE to 3 (NXDOMAIN)
   dns_buf[3] |= 0b0000_0011;

   Some(())
}

/// Check if blocklists are enabled
pub fn is_filtering_enabled() -> bool {
   crate::statics::ARGS.blocklists
}

/// Get the number of loaded blocklists (for diagnostics)
pub async fn get_blocklist_count() -> usize {
   BLOCKLISTS.lock().await.len()
}

/// Get the total number of blocked domains (for diagnostics)
pub async fn get_blocked_domain_count() -> usize {
   BLOCKLISTS.lock().await.iter().map(|blocklist| blocklist.blocked_domains.len()).sum()
}
