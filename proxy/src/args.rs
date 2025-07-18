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

use clap::Parser;

/// FaF DNS Proxy - Faster DNS Resolution
#[derive(Parser, Debug, Default)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
   /// daemon mode. No logging output to stdio, no charts.
   #[clap(short, long)]
   pub daemon: bool,

   /// port
   #[clap(short, long, default_value_t = 53)]
   pub port: u16,

   /// enable domain filtering from pre-defined blocklists.
   #[clap(long)]
   pub blocklists: bool,

   /// data directory to store blocklists. Defaults to a system temp directory.
   #[clap(long)]
   pub data_directory: Option<std::path::PathBuf>,

   /// [linux only] attempt to find the source pid and program name for each dns request.
   /// Requests must be local to the same host as faf-dns-proxy.
   /// Requires root to identify privileged processes.
   /// Uses eBPF for high-performance monitoring when available, falls back to netlink (+10ms overhead).
   #[clap(long)]
   pub client_ident: bool,

   /// [linux only] force use of netlink method for client identification, bypassing eBPF fast path.
   /// Only has effect when --client-ident is also specified.
   /// Useful for debugging or systems where eBPF is not available.
   #[clap(long)]
   pub force_netlink: bool,

   /// at regular intervals (shown in non-daemon output), create a chart representing the distribution of DNS query -> response times.
   /// Charts are saved to the data directory.
   #[clap(long)]
   pub charts: bool,

   /// enable SNI (Server Name Indication) in TLS connections to upstream DNS servers.
   #[clap(long)]
   pub sni: bool,
}
