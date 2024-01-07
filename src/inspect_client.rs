lazy_static::lazy_static! {
   static ref ALL_PROCESSES: std::sync::Mutex<Vec<procfs::process::Process>> = std::sync::Mutex::new(procfs::process::all_processes().unwrap().filter_map(Result::ok).collect::<Vec<_>>());
}

// ref: https://man7.org/linux/man-pages/man7/netlink.7.html
// ref: https://man7.org/linux/man-pages/man7/sock_diag.7.html
// ref: https://github.com/rust-netlink/netlink-packet-sock-diag/blob/main/examples/dump_ipv4.rs
pub fn get_socket_info(source_socket: &std::net::SocketAddrV4) -> Option<Box<netlink_packet_sock_diag::inet::InetResponse>> {
   use netlink_packet_core::{NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_DUMP, NLM_F_REQUEST};
   use netlink_packet_sock_diag::{
      constants::*,
      inet::{ExtensionFlags, InetRequest, SocketId, StateFlags},
      SockDiagMessage,
   };
   use netlink_sys::{protocols::NETLINK_SOCK_DIAG, Socket, SocketAddr};

   let mut nlsocket = Socket::new(NETLINK_SOCK_DIAG).unwrap();
   let _port_number = nlsocket.bind_auto().unwrap().port_number();
   nlsocket.connect(&SocketAddr::new(0, 0)).unwrap();

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
         let rx_packet = <NetlinkMessage<SockDiagMessage>>::deserialize(bytes).unwrap();

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
      let new_procs: Vec<procfs::process::Process> = procfs::process::all_processes().unwrap().filter_map(Result::ok).collect::<Vec<_>>();
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
            if let procfs::process::FDTarget::Socket(fd_inode) = fd.unwrap().target {
               if fd_inode == inode {
                  return Some(stat);
               }
            }
         }
      }
   }

   None
}
