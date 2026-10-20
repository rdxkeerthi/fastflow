use crate::error::{FastFlowError, Result};

/// A lightweight, strictly bounds-checked zero-copy cursor over a byte slice.
///
/// Designed for zero-heap-allocation binary decoding where safety, speed,
/// and protection against buffer overruns are paramount.
#[derive(Debug, Clone, Copy)]
pub struct ByteCursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    /// Creates a new cursor starting at offset 0.
    #[inline(always)]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the total length of the underlying slice.
    #[inline(always)]
    pub const fn total_len(&self) -> usize {
        self.data.len()
    }

    /// Returns the current offset position of the cursor.
    #[inline(always)]
    pub const fn position(&self) -> usize {
        self.offset
    }

    /// Returns the number of unread bytes remaining in the buffer.
    #[inline(always)]
    pub const fn remaining(&self) -> usize {
        if self.offset <= self.data.len() {
            self.data.len() - self.offset
        } else {
            0
        }
    }

    /// Checks if there are no bytes left to read.
    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.offset >= self.data.len()
    }

    /// Returns the remaining slice without advancing the cursor.
    #[inline(always)]
    pub fn remaining_slice(&self) -> &'a [u8] {
        if self.offset < self.data.len() {
            &self.data[self.offset..]
        } else {
            &[]
        }
    }

    /// Advances the cursor by `count` bytes, returning an error if out of bounds.
    #[inline(always)]
    pub fn advance(&mut self, count: usize) -> Result<()> {
        let new_offset = self
            .offset
            .checked_add(count)
            .ok_or(FastFlowError::IntegerOverflow("cursor advance overflow"))?;
        if new_offset > self.data.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: count,
                available: self.remaining(),
            });
        }
        self.offset = new_offset;
        Ok(())
    }

    /// Reads a single `u8` byte and advances the cursor.
    #[inline(always)]
    pub fn read_u8(&mut self) -> Result<u8> {
        if self.offset >= self.data.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }
        let b = self.data[self.offset];
        self.offset += 1;
        Ok(b)
    }

    /// Reads a slice of `len` bytes and advances the cursor. Zero allocations.
    #[inline(always)]
    pub fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(FastFlowError::IntegerOverflow("read_bytes overflow"))?;
        if end > self.data.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: len,
                available: self.remaining(),
            });
        }
        let slice = &self.data[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    /// Reads a 16-bit unsigned integer in Big-Endian (Network Byte Order).
    #[inline(always)]
    pub fn read_u16_be(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a 16-bit unsigned integer in Little-Endian.
    #[inline(always)]
    pub fn read_u16_le(&mut self) -> Result<u16> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a 32-bit unsigned integer in Big-Endian (Network Byte Order).
    #[inline(always)]
    pub fn read_u32_be(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a 32-bit unsigned integer in Little-Endian.
    #[inline(always)]
    pub fn read_u32_le(&mut self) -> Result<u32> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a 64-bit unsigned integer in Big-Endian.
    #[inline(always)]
    pub fn read_u64_be(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Reads a 64-bit unsigned integer in Little-Endian.
    #[inline(always)]
    pub fn read_u64_le(&mut self) -> Result<u64> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Peeks a single `u8` without advancing the cursor.
    #[inline(always)]
    pub fn peek_u8(&self) -> Result<u8> {
        if self.offset >= self.data.len() {
            return Err(FastFlowError::BufferUnderflow {
                needed: 1,
                available: 0,
            });
        }
        Ok(self.data[self.offset])
    }
}

/// Safely extracts a sub-slice `[start..start + len]` with strict bounds checking.
#[inline(always)]
pub fn slice_checked(data: &[u8], start: usize, len: usize) -> Result<&[u8]> {
    let end = start
        .checked_add(len)
        .ok_or(FastFlowError::IntegerOverflow("slice bounds overflow"))?;
    if end > data.len() {
        return Err(FastFlowError::BufferUnderflow {
            needed: len,
            available: data.len().saturating_sub(start),
        });
    }
    Ok(&data[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cursor_read_primitives() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0];
        let mut cursor = ByteCursor::new(&data);

        assert_eq!(cursor.read_u8().unwrap(), 0x12);
        assert_eq!(cursor.read_u16_be().unwrap(), 0x3456);
        assert_eq!(cursor.read_u32_be().unwrap(), 0x789ABCDE);
        assert_eq!(cursor.remaining(), 1);
        assert_eq!(cursor.read_u8().unwrap(), 0xF0);
        assert!(cursor.is_empty());
        assert!(cursor.read_u8().is_err());
    }

    #[test]
    fn test_cursor_endianness() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let mut cursor_be = ByteCursor::new(&data);
        assert_eq!(cursor_be.read_u32_be().unwrap(), 0x01020304);

        let mut cursor_le = ByteCursor::new(&data);
        assert_eq!(cursor_le.read_u32_le().unwrap(), 0x04030201);
    }
}
