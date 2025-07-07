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

lazy_static::lazy_static! {
   static ref ALL_PROCESSES: std::sync::Mutex<Vec<procfs::process::Process>> = std::sync::Mutex::new(
      match procfs::process::all_processes() {
         Ok(procs) => procs.filter_map(Result::ok).collect::<Vec<_>>(),
         Err(_) => {
            eprintln!("Warning: Failed to initialize process list at startup");
            Vec::new()
         }
      }
   );
}

// ref: https://man7.org/linux/man-pages/man7/netlink.7.html
// ref: https://man7.org/linux/man-pages/man7/sock_diag.7.html
// ref: https://github.com/rust-netlink/netlink-packet-sock-diag/blob/main/examples/dump_ipv4.rs
pub fn get_socket_info(source_socket: &std::net::SocketAddrV4) -> Option<Box<netlink_packet_sock_diag::inet::InetResponse>> {
   use netlink_packet_core::{NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload};
   use netlink_packet_sock_diag::{
      SockDiagMessage,
      constants::*,
      inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
   };
   use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

   let mut nlsocket = match Socket::new(NETLINK_SOCK_DIAG) {
      Ok(socket) => socket,
      Err(err) => {
         eprintln!("Failed to create netlink socket: {} at {}:{}", err, file!(), line!());
         return None;
      }
   };

   let _port_number = match nlsocket.bind_auto() {
      Ok(addr) => addr.port_number(),
      Err(err) => {
         eprintln!("Failed to bind netlink socket: {} at {}:{}", err, file!(), line!());
         return None;
      }
   };

   if let Err(err) = nlsocket.connect(&SocketAddr::new(0, 0)) {
      eprintln!("Failed to connect netlink socket: {} at {}:{}", err, file!(), line!());
      return None;
   }

   let mut nl_hdr = NetlinkHeader::default();
   nl_hdr.flags = NLM_F_REQUEST | NLM_F_DUMP;
   let mut packet = NetlinkMessage::new(
      nl_hdr,
      SockDiagMessage::InetRequest(InetRequest {
         family: AF_INET,
         protocol: IPPROTO_UDP,
         extensions: ExtensionFlags::empty(),
         states: StateFlags::all(),
         socket_id: SocketId::new_v4(),
      })
      .into(),
   );

   packet.finalize();

   let mut buf = vec![0; packet.header.length as usize];

   // It is important to check that the buffer is big enough for the packet, otherwise `serialize()` panics.
   if buf.len() != packet.buffer_len() {
      eprintln!("buf.len() != packet.buffer_len()");
      return None;
   }

   packet.serialize(&mut buf[..]);

   if nlsocket.send(&buf[..], 0).is_err() {
      return None;
   }

   let mut receive_buffer = vec![0; 4096];
   let mut offset = 0;
   while let Ok(size) = nlsocket.recv(&mut &mut receive_buffer[..], 0) {
      loop {
         let bytes = &receive_buffer[offset..];
         let rx_packet = match <NetlinkMessage<SockDiagMessage>>::deserialize(bytes) {
            Ok(packet) => packet,
            Err(err) => {
               eprintln!("Failed to deserialize netlink message: {} at {}:{}", err, file!(), line!());
               break;
            }
         };

         match rx_packet.payload {
            NetlinkPayload::Noop => {}
            NetlinkPayload::InnerMessage(SockDiagMessage::InetResponse(response)) => {
               let source_ipv4 = match response.header.socket_id.source_address {
                  std::net::IpAddr::V4(ip) => ip,
                  _ => unreachable!(),
               };
               if &source_ipv4 == source_socket.ip()
                  && response.header.socket_id.source_port == source_socket.port()
                  && response.header.socket_id.destination_port == crate::statics::ARGS.port
               {
                  return Some(response);
               }
            }
            NetlinkPayload::Done(_) => {
               return None;
            }
            _ => return None,
         }

         offset += rx_packet.header.length as usize;
         if offset == size || rx_packet.header.length == 0 {
            offset = 0;
            break;
         }
      }
   }

   None
}

// ref: https://github.com/eminence/procfs/blob/master/procfs/examples/netstat.rs
pub fn find_pid_by_socket_inode(inode: u64) -> Option<procfs::process::Stat> {
   let mut stats_maybe: Option<procfs::process::Stat> = if let Ok(all_procs) = ALL_PROCESSES.try_lock() {
      // fast path, if we find the stats in the cached list of processes we can avoid the expensive procfs::process::all_processes() call
      find_stats_for_inode(&all_procs, inode)
   } else {
      None
   };

   if stats_maybe.is_none() {
      // slow path
      let new_procs: Vec<procfs::process::Process> = match procfs::process::all_processes() {
         Ok(procs) => procs.filter_map(Result::ok).collect::<Vec<_>>(),
         Err(err) => {
            eprintln!("Failed to enumerate processes: {} at {}:{}", err, file!(), line!());
            return None;
         }
      };
      stats_maybe = find_stats_for_inode(&new_procs, inode);
      if let Ok(mut all_procs) = ALL_PROCESSES.try_lock() {
         *all_procs = new_procs;
      }
   }

   stats_maybe
}

fn find_stats_for_inode(all_procs: &[procfs::process::Process], inode: u64) -> Option<procfs::process::Stat> {
   for process in all_procs.iter() {
      if let (Ok(stat), Ok(fds)) = (process.stat(), process.fd()) {
         for fd in fds {
            if let Ok(fd_info) = fd {
               if let procfs::process::FDTarget::Socket(fd_inode) = fd_info.target {
                  if fd_inode == inode {
                     return Some(stat);
                  }
               }
            }
         }
      }
   }

   None
}
