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

#[repr(C, align(32))]
pub struct timespec {
   pub tv_sec: i64,
   pub tv_nsec: i64,
}

extern "C" {
   // We use this function instead of a direct syscall because this function uses VDSO, which is faster
   fn clock_gettime(clk_id: i32, tp: *mut timespec) -> i32;
}

const CLOCK_REALTIME: i32 = 0;

#[inline]
pub fn get_epoch_seconds() -> i64 {
   #[allow(invalid_value)]
   let mut ts: timespec = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
   unsafe { clock_gettime(CLOCK_REALTIME, &mut ts as *mut timespec) };

   ts.tv_sec
}

pub fn get_timespec() -> timespec {
   #[allow(invalid_value)]
   let mut ts: timespec = unsafe { core::mem::MaybeUninit::uninit().assume_init() };
   unsafe { clock_gettime(CLOCK_REALTIME, &mut ts as *mut timespec) };
   ts
}

pub fn get_elapsed_ms(later: &timespec, earlier: &timespec) -> i64 {
   (later.tv_sec - earlier.tv_sec) * 1_000 + (later.tv_nsec - earlier.tv_nsec) / 1_000_000
}
