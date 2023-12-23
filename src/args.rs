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
   /// [optional] daemon mode, no logging output.
   #[clap(short, long)]
   pub daemon: bool,

   /// [optional] enable SNI (Server Name Indication) for TLS connections to upstream DNS servers.
   #[clap(long)]
   pub enable_sni: bool,

   /// [optional] enable domain blocklists.
   #[clap(long)]
   pub enable_blocklists: bool,

   /// [optional] data directory to store blocklists. Defaults to the current working directory.
   #[clap(long)]
   pub data_directory: Option<std::path::PathBuf>,
}
