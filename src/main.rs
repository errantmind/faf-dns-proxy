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

mod args;
mod blocklist;
mod cache;
mod chart;
mod dns;
mod network;
mod proxy;
mod statics;
mod stats;
mod tls;
mod util;

#[cfg(target_os = "linux")]
mod inspect_client;

#[cfg(target_os = "linux")]
#[global_allocator]
static GLOBAL: tcmalloc::TCMalloc = tcmalloc::TCMalloc;

pub fn main() {
   if !statics::ARGS.daemon {
      print_banner();
      print_version();
   }

   tokio::runtime::Runtime::new().unwrap().block_on(proxy::go(statics::ARGS.port));
}

fn print_banner() {
   println!();
   println!(
      r"
    ███████╗ █████╗ ███████╗    ██████╗ ███╗   ██╗███████╗
    ██╔════╝██╔══██╗██╔════╝    ██╔══██╗████╗  ██║██╔════╝
    █████╗  ███████║█████╗      ██║  ██║██╔██╗ ██║███████╗
    ██╔══╝  ██╔══██║██╔══╝      ██║  ██║██║╚██╗██║╚════██║
    ██║     ██║  ██║██║         ██████╔╝██║ ╚████║███████║
    ╚═╝     ╚═╝  ╚═╝╚═╝         ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    "
   );
   println!("\n");
}

fn print_version() {
   println!("{} v{} | repo: https://github.com/errantmind/faf-dns-proxy\n", statics::PROJECT_NAME, statics::VERSION,);
}

// Disable stack probing as an optimization.
// https://metricpanda.com/rival-fortress-update-45-dealing-with-__chkstk-__chkstk_ms-when-cross-compiling-for-windows/
#[cfg(target_os = "linux")]
#[no_mangle]
extern "C" fn __chkstk() {}
