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

use crate::const_config::*;
use crate::const_sys::*;
use crate::sys_call;
use crate::util;

#[inline(always)]
pub fn htons(u: u16) -> u16 {
   u.to_be()
}

#[inline(always)]
pub fn htonl(u: u32) -> u32 {
   u.to_be()
}

#[repr(C)]
pub struct in_addr {
   pub s_addr: u32,
}

#[repr(C, align(16))]
pub struct sockaddr_in {
   pub sin_family: u16,
   pub sin_port: u16,
   pub sin_addr: in_addr,
   pub sin_zero: [u8; 8],
}

impl sockaddr_in {
   pub fn new(sin_family: u16, sin_port: u16, s_addr: u32) -> Self {
      Self {
         sin_family,
         sin_port,
         sin_addr: in_addr { s_addr },
         sin_zero: unsafe { core::mem::MaybeUninit::zeroed().assume_init() },
      }
   }
}

#[repr(C, align(16))]
pub struct linger {
   pub l_onoff: i32,
   pub l_linger: i32,
}

const OPTVAL: isize = 1;

const O_NONBLOCK: isize = 2048;
const F_SETFL: isize = 4;
const SOCK_LEN: u32 = core::mem::size_of::<sockaddr_in>() as u32;

#[inline]
pub fn get_addr(host: u32, port: u16) -> sockaddr_in {
   sockaddr_in {
      sin_family: AF_INET as u16,
      sin_port: htons(port),
      sin_addr: in_addr { s_addr: host },
      sin_zero: unsafe { core::mem::zeroed() },
   }
}

#[inline]
pub fn bind_socket(fd: isize, host: u32, port: u16) -> sockaddr_in {
   let size_of_optval = core::mem::size_of_val(&OPTVAL) as u32;

   let res = sys_call!(
      SYS_SETSOCKOPT as isize,
      fd,
      SOL_SOCKET as isize,
      SO_REUSEADDR as isize,
      &OPTVAL as *const _ as _,
      size_of_optval as isize
   );

   if res < 0 {
      panic!("SYS_SETSOCKOPT SO_REUSEADDR");
   }

   let res = sys_call!(
      SYS_SETSOCKOPT as isize,
      fd,
      SOL_SOCKET as isize,
      SO_REUSEPORT as isize,
      &OPTVAL as *const isize as _,
      size_of_optval as isize
   );

   if res < 0 {
      panic!("SYS_SETSOCKOPT SO_REUSEPORT");
   }

   let addr = get_addr(host, port);

   let res = sys_call!(SYS_BIND as isize, fd, &addr as *const _ as _, SOCK_LEN as isize);

   if res < 0 {
      panic!("SYS_BIND");
   }

   addr
}

#[inline]
pub fn get_udp_socket(core: i32) -> isize {
   let fd = sys_call!(SYS_SOCKET as isize, AF_INET as isize, SOCK_DGRAM as isize, IPPROTO_UDP as isize);

   if core >= 0 {
      sys_call!(
         SYS_SETSOCKOPT as isize,
         fd,
         SOL_SOCKET as isize,
         SO_INCOMING_CPU as isize,
         &core as *const _ as _,
         core::mem::size_of_val(&core) as isize
      );
   }

   if fd < 0 {
      panic!("SYS_SOCKET");
   }

   println!("listener fd = {}", fd);

   fd
}

#[inline]
pub fn tcp_connect(host_ip: &str, port: u16) -> isize {
   const OPTVAL_TCPFASTOPEN_QUEUE_LEN: isize = MAX_CONN as isize;

   // Send keepalive probes
   const SO_KEEPALIVE_VAL: isize = 1;

   // The time (in seconds) the connection needs to remain idle before TCP starts sending
   // keepalive probes, if the socket option SO_KEEPALIVE has been set on this socket.
   // This option should not be used in code intended to be portable.
   const TCP_KEEPIDLE_VAL: isize = 3;

   // The maximum number of keepalive probes TCP should send before dropping the connection.
   // This option should not be used in code intended to be portable.
   //const TCP_KEEPCNT_VAL: isize = 200;

   // The time (in seconds) between individual keepalive probes. This option should not be used
   // in code intended to be portable.
   const TCP_KEEPINTVL_VAL: isize = 3;

   unsafe {
      let fd = sys_call!(SYS_SOCKET as isize, AF_INET as isize, SOCK_STREAM as isize, 0);
      debug_assert!(fd >= 0);

      // let res = sys_call!(
      //    SYS_SETSOCKOPT as isize,
      //    fd,
      //    SOL_SOCKET as isize,
      //    SO_KEEPALIVE as isize,
      //    &SO_KEEPALIVE_VAL as *const isize as _,
      //    core::mem::size_of_val(&SO_KEEPALIVE_VAL) as isize as isize
      // );

      // if res < 0 {
      //    panic!("SYS_SETSOCKOPT SO_REUSEPORT, {}", res);
      // }

      // let res = sys_call!(
      //    SYS_SETSOCKOPT as isize,
      //    fd,
      //    IPPROTO_TCP as isize,
      //    TCP_KEEPIDLE as isize,
      //    &TCP_KEEPIDLE_VAL as *const _ as _,
      //    core::mem::size_of_val(&TCP_KEEPIDLE_VAL) as isize
      // );

      // if res < 0 {
      //    panic!("SYS_SETSOCKOPT TCP_KEEPIDLE, {}", res);
      // }

      // let res = sys_call!(
      //    SYS_SETSOCKOPT as isize,
      //    fd,
      //    IPPROTO_TCP as isize,
      //    TCP_KEEPCNT as isize,
      //    &TCP_KEEPCNT_VAL as *const _ as _,
      //    core::mem::size_of_val(&TCP_KEEPCNT_VAL) as isize
      // );

      // if res < 0 {
      //    panic!("SYS_SETSOCKOPT TCP_KEEPCNT, {}", res);
      // }

      // let res = sys_call!(
      //    SYS_SETSOCKOPT as isize,
      //    fd,
      //    IPPROTO_TCP as isize,
      //    TCP_KEEPINTVL as isize,
      //    &TCP_KEEPINTVL_VAL as *const _ as _,
      //    core::mem::size_of_val(&TCP_KEEPINTVL_VAL) as isize
      // );

      // if res < 0 {
      //    panic!("SYS_SETSOCKOPT TCP_KEEPINTVL, {}", res);
      // }

      // let res = sys_call!(
      //    SYS_SETSOCKOPT as isize,
      //    fd,
      //    IPPROTO_TCP as isize,
      //    TCP_FASTOPEN as isize,
      //    &MAX_CONN as *const _ as _,
      //    core::mem::size_of_val(&MAX_CONN) as isize
      // );

      // if res < 0 {
      //    panic!("SYS_SETSOCKOPT TCP_FASTOPEN, {}", res);
      // }

      let res = sys_call!(
         SYS_SETSOCKOPT as isize,
         fd,
         IPPROTO_TCP as isize,
         TCP_NODELAY as isize,
         &OPTVAL as *const _ as _,
         core::mem::size_of_val(&OPTVAL) as isize
      );

      if res < 0 {
         panic!("SYS_SETSOCKOPT TCP_NODELAY, {}", res);
      }

      let addr = sockaddr_in {
         sin_family: AF_INET as u16,
         sin_port: htons(port),
         sin_addr: in_addr { s_addr: util::inet4_aton(host_ip.as_ptr(), host_ip.len()) },
         sin_zero: core::mem::zeroed(),
      };

      let res = sys_call!(SYS_CONNECT as isize, fd, &addr as *const _ as isize, SOCK_LEN as isize);
      if res < 0 {
         panic!("SYS_CONNECT, {}", res);
      }

      const OPTVAL_SOLINGER_TIMEOUT: linger = linger { l_onoff: 1, l_linger: 0 };
      let res = sys_call!(
         SYS_SETSOCKOPT as isize,
         fd,
         SOL_SOCKET as isize,
         SO_LINGER as isize,
         &OPTVAL_SOLINGER_TIMEOUT as *const _ as _,
         core::mem::size_of_val(&OPTVAL_SOLINGER_TIMEOUT) as isize
      );

      if res < 0 {
         panic!("SYS_SETSOCKOPT SO_LINGER, {}", res);
      }

      println!("connect fd = {}", fd);

      //let res = sys_call!(SYS_FCNTL as isize, fd as isize, F_SETFL, O_NONBLOCK);

      // if res < 0 {
      //    panic!("SYS_FCNTL O_NONBLOCK, {}", res);
      // }

      fd
   }
}

#[inline]
pub fn tcp_reconnect(fd: isize, addr: &sockaddr_in) -> bool {
   sys_call!(SYS_CONNECT as isize, fd, addr as *const _ as isize, SOCK_LEN as isize) >= 0
}

// #[inline]
// pub fn setup_connection(fd: isize, core: i32) {
//    //Doesn't help with throughput, just latency per request, and may actually reduce throughput.
//    //May be Useful for this test. I'm not entirely convinced though
//    sys_call!(
//       SYS_SETSOCKOPT as isize,
//       fd,
//       IPPROTO_TCP as isize,
//       TCP_NODELAY as isize,
//       &OPTVAL as *const _ as _,
//       core::mem::size_of_val(&OPTVAL) as isize
//    );

//    sys_call!(
//       SYS_SETSOCKOPT as isize,
//       fd,
//       IPPROTO_TCP as isize,
//       TCP_QUICKACK as isize,
//       &OPTVAL as *const _ as _,
//       core::mem::size_of_val(&OPTVAL) as isize
//    );

//    // This can be disabled if we are passed, say, '-1' for times we don't want to assign a core affinity
//    #[allow(clippy::collapsible_if)]
//    if core >= 0 {
//       sys_call!(
//          SYS_SETSOCKOPT as isize,
//          fd,
//          SOL_SOCKET as isize,
//          SO_INCOMING_CPU as isize,
//          &core as *const _ as _,
//          core::mem::size_of_val(&core) as isize
//       );
//    }

//    //https://stackoverflow.com/a/49900878
//    // sys_call!(
//    //    SYS_SETSOCKOPT as isize,
//    //    fd as isize,
//    //    SOL_SOCKET as isize,
//    //    SO_ZEROCOPY as isize,
//    //    &OPTVAL as *const isize as _,
//    //    core::mem::size_of_val(&OPTVAL) as isize
//    // );

//    // Only useful when using blocking reads, not non-blocking reads as I am
//    // const OPTVAL_BUSYPOLL: isize = 50;
//    // sys_call!(
//    //    SYS_SETSOCKOPT as isize,
//    //    fd,
//    //    SOL_SOCKET as isize,
//    //    SO_BUSY_POLL as isize,
//    //    &OPTVAL_BUSYPOLL as *const _ as _,
//    //    core::mem::size_of_val(&OPTVAL_BUSYPOLL) as isize
//    // );

//    sys_call!(SYS_FCNTL as isize, fd as isize, F_SETFL, O_NONBLOCK);
// }

// #[inline]
// pub fn set_blocking(fd: isize) {
//    sys_call!(SYS_FCNTL as isize, fd as isize, F_SETFL, 0);
// }

// #[inline]
// pub fn set_nonblocking(fd: isize) {
//    sys_call!(SYS_FCNTL as isize, fd as isize, F_SETFL, O_NONBLOCK);
// }

#[inline(always)]
pub fn close_connection(epfd: isize, fd: isize) {
   const OPTVAL_SOLINGER_TIMEOUT: linger = linger { l_onoff: 1, l_linger: 0 };
   sys_call!(
      SYS_SETSOCKOPT as isize,
      fd,
      SOL_SOCKET as isize,
      SO_LINGER as isize,
      &OPTVAL_SOLINGER_TIMEOUT as *const _ as _,
      core::mem::size_of_val(&OPTVAL_SOLINGER_TIMEOUT) as isize
   );

   // Could defer deletes for performance reasons. Wouldn't cause problems as fds are reused. Not going to do this as it would
   // require tracking fd state more granually to avoid the wasted EPOLL_CTL_ADD when new connections come in. I don't know
   // how much of a benefit, performance-wise I'd get
   sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, fd, 0);

   sys_call!(SYS_CLOSE as isize, fd);
}
