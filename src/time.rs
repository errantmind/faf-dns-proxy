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
   return (later.tv_sec - earlier.tv_sec) * 1_000 + (later.tv_nsec - earlier.tv_nsec) / 1_000_000;
}
