/*
FaF is a cutting edge, high performance dns proxy
Copyright (C) 2021  James Bates

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

#![allow(clippy::missing_safety_doc, clippy::uninit_assumed_init, dead_code)]
#![feature(const_size_of_val, const_maybe_uninit_zeroed, core_intrinsics, const_mut_refs, const_for, inline_const, const_socketaddr)]

mod args;
mod const_sys;
mod dns;
mod proxy;
mod statics;
mod time;
mod tls;
mod util;
mod net;
mod stats;


#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub fn main() {
   let args = {
      // Init args

      use clap::Parser;
      unsafe { statics::ARGS = args::Args::parse() };
      args::Args::parse()
   };

   if !args.daemon {
      print_banner();
      print_version();
   }

   util::set_maximum_process_priority();
   tokio::runtime::Runtime::new().unwrap().block_on(proxy::go(53));
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
   println!(
      "{} v{} | checksum: {} | author: errantmind@protonmail.com\n",
      statics::PROJECT_NAME,
      statics::VERSION,
      statics::SELF_CHECKSUM.unwrap()
   );
}
