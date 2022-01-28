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

use crate::dns;
use crate::hasher;
use crate::net;
use crate::sys_call;
use crate::tls;
use crate::util;
use core::intrinsics::likely;
use std::io::Read;
use std::io::Write;

#[repr(C)]
pub union epoll_data {
   pub ptr: isize,
   pub fd: i32,
   pub uint32_t: u32,
   pub uint64_t: u64,
}

#[repr(C, packed)]
pub struct epoll_event {
   pub events: u32,
   pub data: epoll_data,
}

#[inline(never)]
pub fn go(port: u16) {
   // Attempt to set a higher process priority, indicated by a negative number. -20 is the highest possible
   sys_call!(SYS_SETPRIORITY as isize, PRIO_PROCESS as isize, 0, -19);

   //util::set_limits(RLIMIT_STACK, 1024 * 1024 * 16);

   threaded_worker(port, 0);

   // let num_cpu_cores = util::get_num_logical_cpus();
   // for core in 0..num_cpu_cores {
   //    let thread_name = format!("faf{}", core);
   //    let thread_builder = std::thread::Builder::new().name(thread_name).stack_size(1024 * 1024 * 8);
   //    let _ = thread_builder.spawn(move || {
   //       util::set_current_thread_cpu_affinity_to(core);

   //       // Unshare the file descriptor table between threads to keep the fd number itself low, otherwise all
   //       // threads will share the same file descriptor table
   //       sys_call!(SYS_UNSHARE as isize, CLONE_FILES as isize);
   //       threaded_worker(port, core as i32);
   //    });
   // }

   loop {
      std::thread::sleep(core::time::Duration::from_secs(1000000));
   }
}

#[inline(never)]
fn threaded_worker(port: u16, cpu_core: i32) {
   let epfd = sys_call!(SYS_EPOLL_CREATE1 as isize, 0);
   sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, 0, 0);

   let fd_client_udp_listener = net::get_udp_socket(cpu_core);
   net::bind_socket(fd_client_udp_listener, INADDR_ANY, port);

   // Add listener fd to epoll for monitoring
   {
      let epoll_event_listener =
         epoll_event { data: epoll_data { fd: fd_client_udp_listener as i32 }, events: EPOLLIN };

      let _ret = sys_call!(
         SYS_EPOLL_CTL as isize,
         epfd,
         EPOLL_CTL_ADD as isize,
         fd_client_udp_listener as isize,
         &epoll_event_listener as *const epoll_event as isize
      );
   }

   let epoll_events: [epoll_event; MAX_EPOLL_EVENTS_RETURNED] = unsafe { core::mem::zeroed() };
   let epoll_events_ptr = &epoll_events as *const _ as isize;
   let mut saved_event_in_only: epoll_event = unsafe { core::mem::zeroed() };
   saved_event_in_only.events = EPOLLIN;

   let mut buf_client_request: [u8; REQ_BUFF_SIZE] = unsafe { core::mem::zeroed() };
   let buf_client_request_start_address = &buf_client_request as *const _ as isize;

   // We route DNS responses by the id they provided in the initial request. This may occasionally cause
   // timing collisions but they should be very rare. There is a 1 / 2^16 chance of a collision, but even then
   // only if the requests arrive around the exact same time with the same id. Note, cached responses are not
   // affected by this, which makes the odds even lower.
   let mut buf_id_router: [net::sockaddr_in; u16::MAX as usize] = unsafe { core::mem::zeroed() };

   const SOCK_LEN: u32 = core::mem::size_of::<net::sockaddr_in>() as u32;
   let client_addr: net::sockaddr_in = unsafe { core::mem::zeroed() };
   let client_socket_len = SOCK_LEN;

   let tls_client_config = tls::get_tls_client_config();
   let (mut tls_client_conn, mut sock, mut upstream_fd) =
      tls::connect_helper("one.one.one.one", "1.1.1.1", 853, &tls_client_config);

   saved_event_in_only.data.fd = upstream_fd as i32;
   sys_call!(
      SYS_EPOLL_CTL as isize,
      epfd,
      EPOLL_CTL_ADD as isize,
      upstream_fd as isize,
      &saved_event_in_only as *const epoll_event as isize
   );

   let mut query_cache: std::collections::HashMap<&[u8], std::vec::Vec<u8>, std::hash::BuildHasherDefault<hasher::FaFHasher>> =
      hasher::FaFHashMap::default();

   loop {
      let num_incoming_events = sys_call!(
         SYS_EPOLL_WAIT as isize,
         epfd,
         epoll_events_ptr,
         MAX_EPOLL_EVENTS_RETURNED as isize,
         EPOLL_TIMEOUT_MILLIS
      );

      for index in 0..num_incoming_events {
         let cur_fd = unsafe { (*epoll_events.get_unchecked(index as usize)).data.fd } as isize;

         if cur_fd == fd_client_udp_listener {
            println!("waiting on read from fd_client_udp_listener...");

            let read_client = sys_call!(
               SYS_RECVFROM as isize,
               fd_client_udp_listener,
               buf_client_request_start_address,
               REQ_BUFF_SIZE as isize,
               0,
               &client_addr as *const _ as _,
               &client_socket_len as *const _ as _
            );

            if likely(read_client > 0) {
               debug_assert!(read_client <= 512);
               // Extract just the id from the client request
               let id = dns::get_id_big_endian(buf_client_request.as_ptr(), read_client as usize);
               let unique_query_name = dns::get_query_unique_id(buf_client_request.as_ptr(), read_client as usize);
               let cached_response_maybe = query_cache.get(unique_query_name);
               if let Some(cached_response) = cached_response_maybe {
                  let derefed_response = cached_response.as_slice() as *const _ as *const u8;
                  dns::set_id_big_endian(id, derefed_response, cached_response.len());
                  let derefed_response_ptr = derefed_response as *const _ as *mut u8;
                  unsafe { *(derefed_response_ptr as *mut u16) = id };
                  let wrote = sys_call!(
                     SYS_SENDTO as isize,
                     fd_client_udp_listener as isize,
                     derefed_response as isize,
                     cached_response.len() as isize,
                     0,
                     &client_addr as *const _ as isize,
                     client_socket_len as isize
                  );

                  println!("wrote {} CACHED bytes back to client", wrote);
                  continue;
               }

               // Save the client state
               let mut saved_addr = unsafe { buf_id_router.get_unchecked_mut(id as usize) };
               saved_addr.sin_family = client_addr.sin_family;
               saved_addr.sin_port = client_addr.sin_port;
               saved_addr.sin_addr.s_addr = client_addr.sin_addr.s_addr;

               // let query_slice: &mut [u8] =
               //    unsafe { core::slice::from_raw_parts_mut(buf_client_request.as_mut_ptr(), read_client as usize) };

               // let parsed_dns = dns_parser::Packet::parse(query_slice).unwrap();
               // println!("{:?}", parsed_dns);

               println!("===============================================================================");
               println!("TLS DNS");

               let is_connected: bool = match tls_client_conn.process_new_packets() {
                  Ok(io_state) => !io_state.peer_has_closed(),
                  Err(err) => {
                     println!("TLS error: {:?}", err);
                     false
                  }
               };

               if !is_connected {
                  println!("Reconnecting..");
                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_fd, 0);
                  (tls_client_conn, sock, upstream_fd) =
                     tls::connect_helper("one.one.one.one", "1.1.1.1", 853, &tls_client_config);

                  saved_event_in_only.data.fd = upstream_fd as i32;
                  sys_call!(
                     SYS_EPOLL_CTL as isize,
                     epfd,
                     EPOLL_CTL_ADD as isize,
                     upstream_fd as isize,
                     &saved_event_in_only as *const epoll_event as isize
                  );
               }

               // Add length field for TCP transmission as per https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
               // This means putting two bytes at the beginning of the UDP message we received above
               unsafe {
                  core::ptr::copy(
                     buf_client_request.as_ptr(),
                     buf_client_request.as_ptr().add(2) as *mut u8,
                     read_client as usize,
                  )
               };

               // Write both bytes at once after converting to Big Endian
               unsafe {
                  *(buf_client_request.as_mut_ptr() as *mut u16) = net::htons(read_client as u16);
               }

               let query_slice_with_len_added: &mut [u8] =
                  unsafe { core::slice::from_raw_parts_mut(buf_client_request.as_mut_ptr(), read_client as usize + 2) };

               match tls_client_conn.writer().write_all(query_slice_with_len_added) {
                  Ok(_) => println!("write_all {} bytes", query_slice_with_len_added.len()),
                  Err(error) => println!("write_all failed with error {}", error),
               }
               match tls_client_conn.write_tls(&mut sock) {
                  Ok(n) => {
                     println!("write_tls {} bytes", n);
                  }
                  Err(error) => {
                     println!("Reconnecting..");
                     sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_fd, 0);
                     (tls_client_conn, sock, upstream_fd) =
                        tls::connect_helper("one.one.one.one", "1.1.1.1", 853, &tls_client_config);

                     saved_event_in_only.data.fd = upstream_fd as i32;
                     sys_call!(
                        SYS_EPOLL_CTL as isize,
                        epfd,
                        EPOLL_CTL_ADD as isize,
                        upstream_fd as isize,
                        &saved_event_in_only as *const epoll_event as isize
                     );
                     println!("write_tls failed with error {}", error);
                  }
               }
            }

            println!("===============================================================================");
         } else if cur_fd == upstream_fd as isize {
            println!("EPFD ACTIVATED, UPSTREAM FD");

            println!("waiting on read from upstream");

            match tls_client_conn.read_tls(&mut sock) {
               Err(error) => {
                  if error.kind() == std::io::ErrorKind::WouldBlock {
                     println!("WouldBlock");
                     continue;
                  }
                  println!("TLS read error: {:?}", error);
                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_fd, 0);
                  continue;
               }

               Ok(0) => {
                  println!("EOF, handling connection close upstream_fd");
                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_fd, 0);
                  continue;
               }

               Ok(n) => {
                  println!("read {} encrypted bytes from socket", n)
               }
            };

            let io_state = match tls_client_conn.process_new_packets() {
               Ok(io_state) => io_state,
               Err(err) => {
                  println!("TLS error: {:?}", err);
                  continue;
               }
            };

            let bytes_to_read = io_state.plaintext_bytes_to_read();
            if io_state.plaintext_bytes_to_read() > 0 {
               let mut response_bytes = Vec::with_capacity(bytes_to_read);
               // let exact_slice: &mut [u8] = unsafe {
               //    core::slice::from_raw_parts_mut(buf_upstream_response.as_mut_ptr(), bytes_to_read as usize)
               // };
               tls_client_conn.reader().read_exact(response_bytes.as_mut_slice()).unwrap();

               let upstream_response_vec_slice = dns::strip_tcp_dns_size_prefix(&response_bytes);

               let id = dns::get_id_big_endian(upstream_response_vec_slice.as_ptr(), upstream_response_vec_slice.len());

               let wrote = sys_call!(
                  SYS_SENDTO as isize,
                  fd_client_udp_listener as isize,
                  upstream_response_vec_slice.as_ptr() as isize,
                  upstream_response_vec_slice.len() as isize,
                  0,
                  unsafe { buf_id_router.get_unchecked(id as usize) } as *const _ as isize,
                  client_socket_len as isize
               );

               println!("wrote {} bytes back to client", wrote);
               let unique_query_name =
                  dns::get_query_unique_id(upstream_response_vec_slice.as_ptr(), upstream_response_vec_slice.len());
               query_cache.insert(unique_query_name, response_bytes);
            }

            if io_state.peer_has_closed() {
               sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_fd, 0);
               println!("Peer has closed connection");
            }
         }
      }
   }
}
