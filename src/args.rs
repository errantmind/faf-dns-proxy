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
   /// daemon mode, no logging output.
   #[clap(short, long)]
   pub daemon: bool,

   /// port
   #[clap(short, long, default_value_t = 53)]
   pub port: u16,

   /// enable SNI (Server Name Indication) in TLS connections to upstream DNS servers.
   #[clap(long)]
   pub enable_sni: bool,

   /// enable domain filtering from pre-defined blocklists.
   #[clap(long)]
   pub enable_blocklists: bool,

   /// [Linux Only] attempt to find the source pid and program name for each dns request.
   /// Requests must be local to the same host as faf-dns-proxy.
   /// Requires root to identify privileged processes.
   /// Adds significant overhead to each request, ballpark +10ms. Recommended for diagnostic use only.
   #[clap(long)]
   pub client_ident: bool,

   /// data directory to store blocklists. Defaults to the current working directory.
   #[clap(long)]
   pub data_directory: Option<std::path::PathBuf>,
}
