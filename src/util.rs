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
   use xxhash_rust::xxh3::xxh3_64;

   let long_hash = xxh3_64(bytes);
   let bitwise_xor_fold = (long_hash >> 32) ^ (long_hash & (!0u64 >> 32));
   bitwise_xor_fold as u32
}

#[test]
pub fn is_power_of_2_test() {
   assert!(is_power_of_2(1));
   assert!(is_power_of_2(2));
   assert!(is_power_of_2(4));
   assert!(is_power_of_2(8));
   assert!(is_power_of_2(16));
   assert!(is_power_of_2(32));
   assert!(is_power_of_2(64));
   assert!(is_power_of_2(128));
   assert!(is_power_of_2(256));
   assert!(is_power_of_2(512));
   assert!(is_power_of_2(1024));
   assert!(is_power_of_2(2048));
   assert!(is_power_of_2(4096));
   assert!(is_power_of_2(8192));
   assert!(is_power_of_2(16384));
   assert!(is_power_of_2(32768));
   assert!(is_power_of_2(65536));
   assert!(is_power_of_2(131072));
   assert!(is_power_of_2(262144));
   assert!(is_power_of_2(524288));
   assert!(is_power_of_2(1048576));
   assert!(is_power_of_2(2097152));
   assert!(is_power_of_2(4194304));
   assert!(is_power_of_2(8388608));
   assert!(is_power_of_2(16777216));
   assert!(is_power_of_2(33554432));
   assert!(is_power_of_2(67108864));
   assert!(is_power_of_2(134217728));
   assert!(is_power_of_2(268435456));
   assert!(is_power_of_2(536870912));
   assert!(is_power_of_2(1073741824));
   assert!(is_power_of_2(2147483648));
   assert!(is_power_of_2(4294967296));
   assert!(is_power_of_2(8589934592));
   assert!(is_power_of_2(17179869184));
   assert!(is_power_of_2(34359738368));
   assert!(is_power_of_2(68719476736));
   assert!(is_power_of_2(137438953472));
   assert!(is_power_of_2(274877906944));
   assert!(is_power_of_2(549755813888));
   assert!(is_power_of_2(1099511627776));
   assert!(is_power_of_2(2199023255552));
   assert!(is_power_of_2(4398046511104));
   assert!(is_power_of_2(8796093022208));
   assert!(is_power_of_2(17592186044416));
   assert!(is_power_of_2(35184372088832));
   assert!(is_power_of_2(70368744177664));
   assert!(is_power_of_2(140737488355328));
   assert!(is_power_of_2(281474976710656));
   assert!(is_power_of_2(562949953421312));
   assert!(is_power_of_2(1125899906842624));
   assert!(is_power_of_2(2251799813685248));
   assert!(is_power_of_2(4503599627370496));
   assert!(is_power_of_2(9007199254740992));
   assert!(is_power_of_2(18014398509481984));
   assert!(is_power_of_2(36028797018963968));
   assert!(is_power_of_2(72057594037927936));
   assert!(is_power_of_2(144115188075855872));
   assert!(is_power_of_2(288230376151711744));
   assert!(is_power_of_2(576460752303423488));
   assert!(is_power_of_2(1152921504606846976));
   assert!(is_power_of_2(2305843009213693952));
   assert!(is_power_of_2(4611686018427387904));
   assert!(is_power_of_2(9223372036854775808));
}
