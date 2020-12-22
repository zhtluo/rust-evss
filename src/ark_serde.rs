use ark_ff::bytes::{FromBytes, ToBytes};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{marker::PhantomData, vec::Vec};

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::{self, Serializer};

use std::fmt;

pub fn to_bytes<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: ToBytes,
{
    let mut buf: Vec<u8> = Vec::new();
    match data.write(&mut buf) {
        Ok(_) => serializer.serialize_bytes(&buf[..]),
        Err(e) => Err(ser::Error::custom(format!("{}", e))),
    }
}

struct BytesVisitor<T: FromBytes> {
    _t: PhantomData<T>,
}

impl<'de, T: FromBytes> Visitor<'de> for BytesVisitor<T> {
    type Value = T;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a chunk of bytes")
    }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match T::read(v) {
            Ok(i) => Ok(i),
            Err(e) => Err(E::custom(format!("{}", e))),
        }
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf: Vec<u8> = Vec::new();
        let mut val = seq.next_element()?;
        while let Some(i) = val {
            buf.push(i);
            val = seq.next_element()?;
        }
        match T::read(&buf[..]) {
            Ok(i) => Ok(i),
            Err(e) => Err(de::Error::custom(format!("{}", e))),
        }
    }
}

pub fn from_bytes<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromBytes,
{
    deserializer.deserialize_bytes(BytesVisitor::<T> { _t: PhantomData })
}

pub fn canonical_serialize<S, T>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: CanonicalSerialize,
{
    let mut buf: Vec<u8> = Vec::new();
    match data.serialize(&mut buf) {
        Ok(_) => serializer.serialize_bytes(&buf[..]),
        Err(e) => Err(ser::Error::custom(format!("{}", e))),
    }
}

struct CanonicalVisitor<T: CanonicalDeserialize> {
    _t: PhantomData<T>,
}

impl<'de, T: CanonicalDeserialize> Visitor<'de> for CanonicalVisitor<T> {
    type Value = T;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a chunk of bytes")
    }
    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        match T::deserialize(v) {
            Ok(i) => Ok(i),
            Err(e) => Err(E::custom(format!("{}", e))),
        }
    }
    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut buf: Vec<u8> = Vec::new();
        let mut val = seq.next_element()?;
        while let Some(i) = val {
            buf.push(i);
            val = seq.next_element()?;
        }
        match T::deserialize(&buf[..]) {
            Ok(i) => Ok(i),
            Err(e) => Err(de::Error::custom(format!("{}", e))),
        }
    }
}

pub fn canonical_deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: CanonicalDeserialize,
{
    deserializer.deserialize_bytes(CanonicalVisitor::<T> { _t: PhantomData })
}
