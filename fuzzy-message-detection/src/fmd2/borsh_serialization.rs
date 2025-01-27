//! Borsh serialization.

use alloc::string::ToString;

use borsh::io;
use borsh::{BorshDeserialize, BorshSerialize};

use super::*;

impl BorshSerialize for SecretKey {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        BorshSerialize::serialize(&self.to_bytes_flattened(), writer)
    }
}

impl BorshDeserialize for SecretKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Self::from_canonical_bytes_flattened(&bytes).map_err(other)
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        BorshSerialize::serialize(&self.to_bytes_flattened(), writer)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Self::from_bytes_flattened(&bytes).map_err(other)
    }
}

impl BorshSerialize for DetectionKey {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        BorshSerialize::serialize(&self.to_bytes_flattened(), writer)
    }
}

impl BorshDeserialize for DetectionKey {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Self::from_bytes_flattened(&bytes).map_err(other)
    }
}

impl BorshSerialize for FlagCiphertexts {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        BorshSerialize::serialize(&self.to_bytes(), writer)
    }
}

impl BorshDeserialize for FlagCiphertexts {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let bytes: Vec<u8> = BorshDeserialize::deserialize_reader(reader)?;
        Self::from_bytes(&bytes).map_err(other)
    }
}

fn other(err: DeserializationError) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}
