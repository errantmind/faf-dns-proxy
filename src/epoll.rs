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
use crate::stats;
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

static mut STATS: [stats::Stats; UPSTREAM_DNS_SERVERS.len()] = stats::init_stats();

lazy_static::lazy_static! {
   static ref DNS_QUERY_CACHE: std::sync::Mutex<hasher::FaFHashMap<&'static [u8], Vec<u8>>> =
      std::sync::Mutex::new(hasher::FaFHashMap::default());

   // We route DNS responses by the id they provided in the initial request. This may occasionally cause
   // timing collisions but they should be very rare. There is a 1 / 2^16 chance of a collision, but even then
   // only if the requests arrive around the exact same time with the same id. Note, cached responses are not
   // affected by this, which makes the odds even lower.
   static ref BUF_ID_ROUTER: std::sync::Mutex<Vec<net::sockaddr_in>> = {
      let mut router: Vec<net::sockaddr_in> = Vec::with_capacity(u16::MAX as usize);
      for _ in 0..u16::MAX {
         let sockaddr: net::sockaddr_in = unsafe { core::mem::zeroed() };
         router.push(sockaddr);
      }
      std::sync::Mutex::new(router)
   };
}

#[inline(never)]
pub fn go(port: u16) {
   util::set_maximum_process_priority();

   let client_udp_socket = net::get_udp_server_socket(CPU_CORE_CLIENT_LISTENER as i32, INADDR_ANY, port);

   let mut upstream_worker_epfds = Vec::with_capacity(UPSTREAM_DNS_SERVERS.len());
   for _ in 0..UPSTREAM_DNS_SERVERS.len() {
      let upstream_worker_epfd = sys_call!(SYS_EPOLL_CREATE1 as isize, 0);
      upstream_worker_epfds.push(upstream_worker_epfd);
   }

   // Note, 'itc' = 'inter-thread communication'
   let mut itc_server_sockets = Vec::with_capacity(UPSTREAM_DNS_SERVERS.len());
   let mut itc_client_sockets = Vec::with_capacity(UPSTREAM_DNS_SERVERS.len());
   for _ in 0..UPSTREAM_DNS_SERVERS.len() {
      let sockets: [u32; 2] = [0, 0];
      sys_call!(SYS_SOCKETPAIR as isize, AF_UNIX as isize, SOCK_DGRAM as isize, 0, sockets.as_ptr() as isize);

      itc_server_sockets.push(sockets[0]);
      itc_client_sockets.push(sockets[1]);
   }

   for i in 0..UPSTREAM_DNS_SERVERS.len() {
      let upstream_worker_epfd = upstream_worker_epfds[i];
      let itc_fd = itc_server_sockets[i];
      let client_udp_socket_fd = client_udp_socket.fd;
      let thread_name = format!("faf{}", UPSTREAM_DNS_SERVERS[i].1);
      let thread_builder = std::thread::Builder::new().name(thread_name).stack_size(1024 * 1024 * 1);
      let _ = thread_builder.spawn(move || {
         tls_worker(upstream_worker_epfd, itc_fd as isize, client_udp_socket_fd, &UPSTREAM_DNS_SERVERS[i]);
      });
   }

   // Unshare the file descriptor table between threads to keep the fd number itself low, otherwise all
   //       // threads will share the same file descriptor table
   //sys_call!(SYS_UNSHARE as isize, CLONE_FILES as isize);

   //util::set_current_thread_cpu_affinity_to(CPU_CORE);
   //util::set_limits(RLIMIT_STACK, 1024 * 1024 * 16);

   let epfd = sys_call!(SYS_EPOLL_CREATE1 as isize, 0);

   // Add listener fd to epoll for monitoring
   {
      let epoll_event_listener = epoll_event { data: epoll_data { fd: client_udp_socket.fd as i32 }, events: EPOLLIN };

      let _ret = sys_call!(
         SYS_EPOLL_CTL as isize,
         epfd,
         EPOLL_CTL_ADD as isize,
         client_udp_socket.fd as isize,
         &epoll_event_listener as *const epoll_event as isize
      );
   }

   let epoll_events: [epoll_event; MAX_EPOLL_EVENTS_RETURNED] = unsafe { core::mem::zeroed() };
   let epoll_events_start_address = epoll_events.as_ptr() as isize;

   let mut saved_event_in_only: epoll_event = unsafe { core::mem::zeroed() };
   saved_event_in_only.events = EPOLLIN;

   let buf_client_request: [u8; REQ_BUFF_SIZE] = unsafe { core::mem::zeroed() };
   let buf_client_request_start_address = buf_client_request.as_ptr() as isize;

   let client_addr: net::sockaddr_in = unsafe { core::mem::zeroed() };
   let client_socket_len = net::SOCKADDR_IN_LEN;

   loop {
      let num_incoming_events = sys_call!(
         SYS_EPOLL_WAIT as isize,
         epfd,
         epoll_events_start_address,
         MAX_EPOLL_EVENTS_RETURNED as isize,
         EPOLL_TIMEOUT_MILLIS
      );

      for index in 0..num_incoming_events {
         let cur_fd = unsafe { (*epoll_events.get_unchecked(index as usize)).data.fd } as isize;

         if cur_fd == client_udp_socket.fd {
            let read_client = sys_call!(
               SYS_RECVFROM as isize,
               client_udp_socket.fd,
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

               // Scope for cache guard
               {
                  let mut cache_guard = DNS_QUERY_CACHE.lock().unwrap();
                  let cached_response_maybe = cache_guard.get_mut(unique_query_name);

                  if let Some(cached_response) = cached_response_maybe {
                     let response_bytes_stripped_tcp_prefix = dns::remove_tcp_dns_size_prefix(cached_response);
                     dns::set_id_big_endian(id, response_bytes_stripped_tcp_prefix);

                     let _wrote = sys_call!(
                        SYS_SENDTO as isize,
                        client_udp_socket.fd as isize,
                        response_bytes_stripped_tcp_prefix.as_ptr() as isize,
                        response_bytes_stripped_tcp_prefix.len() as isize,
                        0,
                        &client_addr as *const _ as isize,
                        net::SOCKADDR_IN_LEN as isize
                     );

                     continue;
                  }
               }

               // Save the client state
               {
                  let mut id_router_guard = BUF_ID_ROUTER.lock().unwrap();
                  let mut saved_addr = id_router_guard.get_mut(id as usize).unwrap();
                  saved_addr.sin_family = client_addr.sin_family;
                  saved_addr.sin_port = client_addr.sin_port;
                  saved_addr.sin_addr.s_addr = client_addr.sin_addr.s_addr;
               }

               // Write to ITC sockets for upstream DNS resolution
               {
                  for unix_socket in itc_client_sockets.iter() {
                     let wrote = sys_call!(
                        SYS_WRITE as isize,
                        *unix_socket as isize,
                        buf_client_request_start_address,
                        read_client as isize
                     );
                  }
               }
            }
         }
      }
   }
}

pub fn tls_worker(epfd: isize, itc_fd: isize, fd_client_udp_listener: isize, upstream_server: &UpstreamDnsServer) {
   util::unshare_file_descriptors();

   let epoll_events: [epoll_event; MAX_EPOLL_EVENTS_RETURNED] = unsafe { core::mem::zeroed() };
   let epoll_events_ptr = epoll_events.as_ptr() as isize;
   let mut saved_event_in_only: epoll_event = unsafe { core::mem::zeroed() };
   saved_event_in_only.events = EPOLLIN;

   // Add upstream_worker_unix_socket to epoll for monitoring
   {
      saved_event_in_only.data.fd = itc_fd as i32;

      let _ret = sys_call!(
         SYS_EPOLL_CTL as isize,
         epfd,
         EPOLL_CTL_ADD as isize,
         itc_fd as isize,
         &saved_event_in_only as *const epoll_event as isize
      );
   }

   let tls_client_config = tls::get_tls_client_config();
   let mut upstream_state = tls::connect_helper(upstream_server, 853, &tls_client_config);

   // Add tls socket to epoll for monitoring
   {
      saved_event_in_only.data.fd = upstream_state.fd as i32;

      sys_call!(
         SYS_EPOLL_CTL as isize,
         epfd,
         EPOLL_CTL_ADD as isize,
         upstream_state.fd as isize,
         &saved_event_in_only as *const epoll_event as isize
      );
   }

   let mut buf_itc_in: [u8; REQ_BUFF_SIZE] = unsafe { core::mem::zeroed() };
   let buf_itc_in_start_address = buf_itc_in.as_ptr() as isize;

   loop {
      let num_incoming_events = sys_call!(
         SYS_EPOLL_WAIT as isize,
         epfd,
         epoll_events_ptr,
         MAX_EPOLL_EVENTS_RETURNED as isize,
         EPOLL_TIMEOUT_MILLIS
      );

      let mut upstream_dns_conn_good_state = true;

      for index in 0..num_incoming_events {
         let cur_fd = unsafe { (*epoll_events.get_unchecked(index as usize)).data.fd } as isize;

         if cur_fd == itc_fd {
            let read_client = sys_call!(SYS_READ as isize, itc_fd, buf_itc_in_start_address, REQ_BUFF_SIZE as isize);

            if likely(read_client > 0) {
               debug_assert!(read_client <= 512);

               let is_connected: bool = match upstream_state.tls_conn.process_new_packets() {
                  Ok(io_state) => !io_state.peer_has_closed(),
                  Err(err) => {
                     println!("TLS error: {:?}", err);
                     false
                  }
               };
               if !is_connected {
                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
                  upstream_state = tls::connect_helper(upstream_server, 853, &tls_client_config);

                  saved_event_in_only.data.fd = upstream_state.fd as i32;
                  sys_call!(
                     SYS_EPOLL_CTL as isize,
                     epfd,
                     EPOLL_CTL_ADD as isize,
                     upstream_state.fd as isize,
                     &saved_event_in_only as *const epoll_event as isize
                  );
               }

               // Add length field for TCP transmission as per https://datatracker.ietf.org/doc/html/rfc1035#section-4.2.2
               // This means putting two bytes at the beginning of the UDP message we received above
               unsafe {
                  core::ptr::copy(buf_itc_in.as_ptr(), buf_itc_in.as_ptr().add(2) as *mut u8, read_client as usize)
               };

               // Write both bytes at once after converting to Big Endian
               unsafe { *(buf_itc_in.as_mut_ptr() as *mut u16) = net::htons(read_client as u16) };

               let query_slice_with_len_added: &mut [u8] =
                  unsafe { core::slice::from_raw_parts_mut(buf_itc_in.as_mut_ptr(), read_client as usize + 2) };

               match upstream_state.tls_conn.writer().write_all(query_slice_with_len_added) {
                  Ok(_) => (),
                  Err(error) => continue,
               }

               match upstream_state.tls_conn.write_tls(&mut upstream_state.sock) {
                  Ok(_) => {}
                  Err(error) => {
                     sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
                     upstream_state = tls::connect_helper(upstream_server, 853, &tls_client_config);

                     saved_event_in_only.data.fd = upstream_state.fd as i32;
                     sys_call!(
                        SYS_EPOLL_CTL as isize,
                        epfd,
                        EPOLL_CTL_ADD as isize,
                        upstream_state.fd as isize,
                        &saved_event_in_only as *const epoll_event as isize
                     );

                     match upstream_state.tls_conn.writer().write_all(query_slice_with_len_added) {
                        Ok(_) => (), //println!("write_all {} bytes", query_slice_with_len_added.len()),
                        Err(error) => println!("write_all failed with error {}", error),
                     }

                     match upstream_state.tls_conn.write_tls(&mut upstream_state.sock) {
                        Ok(_) => {}
                        Err(error) => {
                           sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
                           upstream_state = tls::connect_helper(upstream_server, 853, &tls_client_config);

                           saved_event_in_only.data.fd = upstream_state.fd as i32;
                           sys_call!(
                              SYS_EPOLL_CTL as isize,
                              epfd,
                              EPOLL_CTL_ADD as isize,
                              upstream_state.fd as isize,
                              &saved_event_in_only as *const epoll_event as isize
                           );
                           println!(
                              "write_tls failed with error on core {} | {} \n NOT RETRYING",
                              CPU_CORE_CLIENT_LISTENER, error
                           );
                        }
                     }
                  }
               }
            }
         } else if cur_fd == upstream_state.fd && upstream_dns_conn_good_state == true {
            match upstream_state.tls_conn.read_tls(&mut upstream_state.sock) {
               Err(error) => {
                  if error.kind() == std::io::ErrorKind::WouldBlock {
                     continue;
                  }

                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
                  let _ = upstream_state.tls_conn.complete_io(&mut upstream_state.sock);
                  upstream_dns_conn_good_state = false;
                  continue;
               }

               Ok(0) => {
                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
                  let _ = upstream_state.tls_conn.complete_io(&mut upstream_state.sock);
                  upstream_dns_conn_good_state = false;
                  continue;
               }

               Ok(_) => {}
            };

            let io_state = match upstream_state.tls_conn.process_new_packets() {
               Ok(io_state) => io_state,
               Err(err) => {
                  sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
                  upstream_dns_conn_good_state = false;
                  println!("TLS error: {:?}", err);
                  continue;
               }
            };

            let bytes_to_read = io_state.plaintext_bytes_to_read();
            if bytes_to_read > 0 {
               let mut response_buffer = Vec::with_capacity(bytes_to_read);
               unsafe { response_buffer.set_len(bytes_to_read) };
               upstream_state.tls_conn.reader().read_exact(&mut response_buffer).unwrap();

               // We loop here in case there are multiple responses back-to-back in our buffer
               loop {
                  let response_slice_size = {
                     let tcp_reported_len = dns::get_tcp_dns_size_prefix_le(&response_buffer);
                     tcp_reported_len + 2
                  };

                  let more_responses = response_buffer.drain(response_slice_size..).collect();

                  let response_stripped = {
                     let response_slice = &mut response_buffer[0..response_slice_size];
                     dns::remove_tcp_dns_size_prefix(response_slice)
                  };

                  // Scope for guards
                  {
                     let id = dns::get_id_big_endian(response_stripped.as_ptr(), response_stripped.len());

                     let mut id_router_guard = BUF_ID_ROUTER.lock().unwrap();
                     let saved_addr = id_router_guard.get_mut(id as usize).unwrap();

                     {
                        let cache_key = dns::get_query_unique_id(response_stripped.as_ptr(), response_stripped.len());
                        let mut cache_guard = DNS_QUERY_CACHE.lock().unwrap();
                        if !cache_guard.contains_key(cache_key) {
                           let _wrote = sys_call!(
                              SYS_SENDTO as isize,
                              fd_client_udp_listener as isize,
                              response_stripped.as_ptr() as isize,
                              response_stripped.len() as isize,
                              0,
                              saved_addr as *const _ as isize,
                              net::SOCKADDR_IN_LEN as isize
                           );

                           cache_guard.insert(cache_key, response_buffer);
                           unsafe { stats::Stats::array_increment_fastest(&mut STATS, upstream_server.1) };
                        }
                     }
                  }

                  response_buffer = more_responses;

                  if response_buffer.is_empty() {
                     break;
                  }
               }
            }

            if io_state.peer_has_closed() {
               sys_call!(SYS_EPOLL_CTL as isize, epfd, EPOLL_CTL_DEL as isize, upstream_state.fd, 0);
               let _ = upstream_state.tls_conn.complete_io(&mut upstream_state.sock);
               upstream_dns_conn_good_state = false;
            }
         }
      }

      if num_incoming_events == 0 {
         unsafe {
            print!("{}[2J", 27 as char);
            for stat in STATS.as_slice() {
               println!("{}\n", stat);
            }
         }
      }
   }
}
