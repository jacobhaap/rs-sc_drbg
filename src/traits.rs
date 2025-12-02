use std::{cmp::PartialEq, ops::Rem};

/// A trait for unsigned integers, providing common arithmetic and byte
/// conversion functionality.
///
/// Abstracts over `u32` and `u64`, enabling generic code that works with
/// different unsigned integer types.
pub trait UnsignedInt:
    Copy + From<u32> + Rem<Output = Self> + PartialEq
{
    const MAX: Self;
    const SIZE: usize;
    fn wrapping_add(self, other: Self) -> Self;
    fn wrapping_sub(self, other: Self) -> Self;
    fn to_le_bytes(self) -> Vec<u8>;
    fn to_be_bytes(self) -> Vec<u8>;
    fn from_le_bytes(bytes: &[u8]) -> Self;
    fn from_be_bytes(bytes: &[u8]) -> Self;
    fn as_usize(self) -> usize;
    fn from_usize(v: usize) -> Self;
}

impl UnsignedInt for u32 {
    const MAX: u32 = u32::MAX;
    const SIZE: usize = 4;
    fn wrapping_add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }
    fn wrapping_sub(self, other: Self) -> Self {
        self.wrapping_sub(other)
    }
    fn to_le_bytes(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
    fn to_be_bytes(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn from_le_bytes(bytes: &[u8]) -> Self {
        u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .expect("slice must be exactly 4 bytes for u32 conversion"),
        )
    }
    fn from_be_bytes(bytes: &[u8]) -> Self {
        u32::from_be_bytes(
            bytes[..4]
                .try_into()
                .expect("slice must be exactly 4 bytes for u32 conversion"),
        )
    }
    fn as_usize(self) -> usize {
        self as usize
    }
    fn from_usize(v: usize) -> Self {
        v as u32
    }
}

impl UnsignedInt for u64 {
    const MAX: u64 = u64::MAX;
    const SIZE: usize = 8;
    fn wrapping_add(self, other: Self) -> Self {
        self.wrapping_add(other)
    }
    fn wrapping_sub(self, other: Self) -> Self {
        self.wrapping_sub(other)
    }
    fn to_le_bytes(self) -> Vec<u8> {
        self.to_le_bytes().to_vec()
    }
    fn to_be_bytes(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
    fn from_le_bytes(bytes: &[u8]) -> Self {
        u64::from_le_bytes(
            bytes[..8]
                .try_into()
                .expect("slice must be exactly 4 bytes for u64 conversion"),
        )
    }
    fn from_be_bytes(bytes: &[u8]) -> Self {
        u64::from_be_bytes(
            bytes[..8]
                .try_into()
                .expect("slice must be exactly 4 bytes for u64 conversion"),
        )
    }
    fn as_usize(self) -> usize {
        self as usize
    }
    fn from_usize(v: usize) -> Self {
        v as u64
    }
}
