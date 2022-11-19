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

use crate::net;
use crate::statics::*;

use hashbrown::HashMap;
use std::os::unix::prelude::FromRawFd;

pub struct TlsConnectionWrapper {
   pub fd: isize,
   pub tls_conn: rustls::ClientConnection,
   pub sock: std::net::TcpStream,
}

#[inline]
pub fn connect_helper(
   upstream_server: &UpstreamDnsServer,
   tls_server_port: u16,
   tls_client_config: &rustls::ClientConfig,
) -> TlsConnectionWrapper {
   let mut tls_conn = {
      let upstream_dns_address: rustls::ServerName = upstream_server.0.try_into().unwrap();
      let arc_config = std::sync::Arc::new(tls_client_config.clone());
      rustls::ClientConnection::new(arc_config, upstream_dns_address).unwrap()
   };
   let fd = net::tcp_connect(upstream_server.1, tls_server_port);
   let mut sock = unsafe { std::net::TcpStream::from_raw_fd(fd as i32) };
   while tls_conn.is_handshaking() {
      let res = tls_conn.complete_io(&mut sock);
      if res.is_err() {
         panic!("complete_handshake FAILED: {}", res.err().unwrap());
         //std::thread::sleep(std::time::Duration::from_micros(10));
      }
   }

   TlsConnectionWrapper { fd, tls_conn, sock }
}

#[inline]
pub fn get_tls_client_config() -> rustls::ClientConfig {
   let mut root_store = rustls::RootCertStore { roots: Vec::new() };
   root_store.roots.extend(
      webpki_roots::TLS_SERVER_ROOTS
         .0
         .iter()
         .map(|ta| rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)),
   );
   let mut config = rustls::ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store.clone()).with_no_client_auth();
   config.session_storage = std::sync::Arc::new(PersistCache::new());
   config.enable_early_data = true;

   config
}

struct PersistCache {
   cache: std::sync::Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl PersistCache {
   fn new() -> Self {
      PersistCache { cache: std::sync::Mutex::new(HashMap::new()) }
   }

   fn len(&self) -> Option<usize> {
      match self.cache.lock() {
         Ok(n) => Some(n.len()),
         Err(_) => None,
      }
   }
}

impl rustls::client::StoresClientSessions for PersistCache {
   fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
      self.cache.lock().unwrap().insert(key, value);
      true
   }

   fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
      // {
      //    println!("{} entries in cache", self.len().unwrap());
      // }
      self.cache.lock().unwrap().get(key).cloned()
   }
}
