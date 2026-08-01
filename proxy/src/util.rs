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

/// Gets duration since UNIX_EPOCH in milliseconds
#[inline]
pub fn _get_unix_ts_nanos() -> u128 {
   std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_nanos()
}

/// Gets duration since UNIX_EPOCH in milliseconds
#[inline]
pub fn get_unix_ts_millis() -> u128 {
   std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_millis()
}

/// Gets duration since UNIX_EPOCH in seconds
#[inline]
pub fn get_unix_ts_secs() -> u64 {
   std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs()
}

#[inline]
pub fn is_power_of_2(num: u64) -> bool {
   num & (num - 1) == 0
}

#[inline]
pub fn encode_id_and_hash32_to_u64(id: u16, hash32: u32) -> u64 {
   let id = id as u64;
   let hash32 = hash32 as u64;
   (id << 32) | hash32
}

#[inline(always)]
pub fn hash32(bytes: &[u8]) -> u32 {
   let long_hash = rapidhash::v3::rapidhash_v3(bytes);
   let bitwise_xor_fold = (long_hash >> 32) ^ (long_hash & (!0u64 >> 32));
   bitwise_xor_fold as u32
}
