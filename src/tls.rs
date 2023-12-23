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

#[inline]
pub fn get_tls_client_config() -> tokio_rustls::rustls::ClientConfig {
   let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
   root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

   let mut config = tokio_rustls::rustls::ClientConfig::builder().with_root_certificates(root_store).with_no_client_auth();

   config.resumption = tokio_rustls::rustls::client::Resumption::default();
   config.enable_sni = crate::statics::ARGS.enable_sni;
   config.enable_early_data = true;

   config
}
