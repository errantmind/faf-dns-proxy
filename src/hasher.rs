use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasherDefault, Hasher};

#[derive(Default)]
pub struct FaFHasher(pub u64);

pub type FaFBuildHasher = BuildHasherDefault<FaFHasher>;
pub type FaFHashMap<K, V> = HashMap<K, V, FaFBuildHasher>;
pub type FaFHashSet<V> = HashSet<V, FaFBuildHasher>;

// murmurhash, but used here incorrectly to mix bits
#[inline]
fn hash_naive(mut to_hash: u64) -> u64 {
   to_hash ^= to_hash >> 33;
   to_hash = to_hash.wrapping_mul(0xff51afd7ed558ccd);
   to_hash ^= to_hash >> 33;
   to_hash = to_hash.wrapping_mul(0xff51afd7ed558ccd);
   to_hash ^= to_hash >> 33;
   to_hash
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
         self.0 = hash_naive(unsafe { *(bytes.as_ptr() as *const u64) });
         bytes = &bytes[8..];
      }

      if bytes.len() >= 4 {
         self.0 = hash_naive(unsafe { *(bytes.as_ptr() as *const u32) as u64 });
         bytes = &bytes[4..];
      }

      if bytes.len() >= 2 {
         self.0 = hash_naive(unsafe { *(bytes.as_ptr() as *const u16) as u64 });
         bytes = &bytes[2..];
      }

      if let Some(&byte) = bytes.first() {
         self.0 = hash_naive(byte as u64);
      }
   }
}
