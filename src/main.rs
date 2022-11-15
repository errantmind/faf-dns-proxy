/*
FaF is a cutting edge, high performance web server
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
#![feature(
   const_size_of_val,
   core_intrinsics,
   const_mut_refs,
   const_for,
   inline_const
)]

mod const_config;
mod const_sys;
mod dns;
mod epoll;
mod u64toa;
mod net;
mod stats;
mod tls;
mod util;

pub fn main() {
   epoll::go(53);
}
