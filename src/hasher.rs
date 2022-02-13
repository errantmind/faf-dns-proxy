use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Default)]
pub struct FaFHasher(pub u64);

pub type FaFBuildHasher = BuildHasherDefault<FaFHasher>;
pub type FaFHashMap<K, V> = HashMap<K, V, FaFBuildHasher>;
pub type FaFHashSet<V> = HashSet<V, FaFBuildHasher>;

// murmurhash finalizer, but used here 'incorrectly' as a complete hashing algorithm
#[inline]
const fn murmur_mix_bits(mut mix_me: u64) -> u64 {
   mix_me ^= mix_me >> 33;
   mix_me = mix_me.wrapping_mul(0xff51afd7ed558ccd);
   mix_me ^= mix_me >> 33;
   mix_me = mix_me.wrapping_mul(0xc4ceb9fe1a85ec53);
   mix_me ^= mix_me >> 33;
   mix_me
}

#[inline]
const fn nasam_mix_bits(mut mix_me: u64) -> u64 {
   mix_me ^= mix_me.rotate_right(25) ^ mix_me.rotate_right(47);
   mix_me *= 0x9E6C63D0676A9A99;
   mix_me ^= mix_me >> 23 ^ mix_me >> 51;
   mix_me *= 0x9E6D62D06F6A9A9B;
   mix_me ^= mix_me >> 23 ^ mix_me >> 51;
   mix_me
}

impl FaFHasher {
   pub const fn new() -> Self {
      FaFHasher(0)
   }
}

impl Hasher for FaFHasher {
   #[inline]
   fn finish(&self) -> u64 {
      self.0
   }

   #[inline]
   fn write(&mut self, mut bytes: &[u8]) {
      while bytes.len() >= 8 {
         self.0 = murmur_mix_bits(unsafe { *(bytes.as_ptr() as *const u64) });
         bytes = &bytes[8..];
      }

      if bytes.len() >= 4 {
         self.0 = murmur_mix_bits(unsafe { *(bytes.as_ptr() as *const u32) as u64 });
         bytes = &bytes[4..];
      }

      if bytes.len() >= 2 {
         self.0 = murmur_mix_bits(unsafe { *(bytes.as_ptr() as *const u16) as u64 });
         bytes = &bytes[2..];
      }

      if let Some(&byte) = bytes.first() {
         self.0 = murmur_mix_bits(byte as u64);
      }
   }
}
