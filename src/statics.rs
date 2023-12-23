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

pub const PROJECT_NAME: &str = env!("CARGO_PKG_NAME");
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub static ARGS: once_cell::sync::Lazy<crate::args::Args> = once_cell::sync::Lazy::new(clap::Parser::parse);

#[derive(Clone, Copy)]
pub struct UpstreamDnsServer {
   pub server_name: &'static str,
   pub socket_addr: std::net::SocketAddrV4,
}

pub const DNS_SERVERS: [UpstreamDnsServer; 6] = [
   UpstreamDnsServer { server_name: "one.one.one.one", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 1, 1, 1), 853) },
   UpstreamDnsServer { server_name: "one.one.one.one", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(1, 0, 0, 1), 853) },
   UpstreamDnsServer { server_name: "dns.google", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 8, 8), 853) },
   UpstreamDnsServer { server_name: "dns.google", socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(8, 8, 4, 4), 853) },
   UpstreamDnsServer {
      server_name: "p0.freedns.controld.com",
      socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(76, 76, 2, 0), 853),
   },
   UpstreamDnsServer {
      server_name: "p0.freedns.controld.com",
      socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(76, 76, 10, 0), 853),
   },
   // Too slow
   // UpstreamDnsServer {
   //    server_name: "dns.mullvad.net",
   //    socket_addr: std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(194, 242, 2, 2), 853),
   // },
];

/// Blocklists to use for DNS filtering. The fiiles are downloaded and parsed at startup (if they have been updated upstream),
/// then cached in memory. They must be a list of domains, one per line. Comments (lines starting with #) are automatically removed.
pub const BLOCKLISTS: [&str; 3] = [
   "https://v.firebog.net/hosts/AdguardDNS.txt",
   "https://v.firebog.net/hosts/Easylist.txt",
   "https://v.firebog.net/hosts/Easyprivacy.txt",
];

/// Overrides TTL on DNS records to the value specified, if DNS record has a value lower than the value specified.
/// To disable, set the value below to 0.
pub const MINIMUM_TTL_OVERRIDE: u64 = 300;
