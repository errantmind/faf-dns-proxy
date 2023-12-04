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

#[derive(Clone, Copy)]
pub struct UpstreamDnsServer {
   pub server_name: &'static str,
   pub socket_addr: std::net::SocketAddrV4,
}

pub struct ResolverConfig {
   /// List of upstream DNS servers to use
   servers: Vec<UpstreamDnsServer>,

   /// Overrides TTL on DNS records to the value specified, if DNS record has a value lower than the value specified.
   /// To disable, set to `None`.
   min_ttl_override: Option<u64>,

   max_queue_depth: usize,
}

impl ResolverConfig {
   pub fn new(servers: Vec<UpstreamDnsServer>, min_ttl_override: Option<u64>, max_queue_depth: usize) -> Self {
      Self { servers, min_ttl_override, max_queue_depth }
   }

   pub fn get_default_servers() -> Vec<UpstreamDnsServer> {
      vec![
         UpstreamDnsServer {
            server_name: "one.one.one.one",
            socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 1, 1, 1), 853),
         },
         UpstreamDnsServer {
            server_name: "one.one.one.one",
            socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 0, 0, 1), 853),
         },
         UpstreamDnsServer {
            server_name: "dns.google",
            socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 8, 8), 853),
         },
         UpstreamDnsServer {
            server_name: "dns.google",
            socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 4, 4), 853),
         },
         UpstreamDnsServer {
            server_name: "dns.quad9.net",
            socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(9, 9, 9, 9), 853),
         },
      ]
   }

   pub fn get_default_max_queue_depth() -> usize {
      4096
   }

   pub fn get_servers(&self) -> &Vec<UpstreamDnsServer> {
      &self.servers
   }

   pub fn get_min_ttl_override(&self) -> Option<u64> {
      self.min_ttl_override
   }

   pub fn get_max_queue_depth(&self) -> usize {
      self.max_queue_depth
   }
}

impl Default for ResolverConfig {
   fn default() -> Self {
      Self { servers: Self::get_default_servers(), min_ttl_override: None, max_queue_depth: Self::get_default_max_queue_depth() }
   }
}
