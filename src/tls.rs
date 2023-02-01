/*
FaF is a high performance DNS over TLS proxy
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

use hashbrown::HashMap;

pub struct TlsConnectionWrapper {
   pub fd: isize,
   pub tls_conn: rustls::ClientConnection,
   pub sock: std::net::TcpStream,
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
