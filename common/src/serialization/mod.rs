use crate::serialization::bincode::{deserialize_from_bincode_bytes, serialize_to_bincode_bytes};
use crate::serialization::mpk::{deserialize_from_msgpack_bytes, serialize_to_msgpack_bytes};
use anyhow::{Context, Result, bail};

pub mod bincode;
pub mod json_bytes;
pub mod mpk;

#[derive(Clone, Copy)]
pub enum Format {
    Msgpack,
    Bincode,
}

pub trait ArgBytes: Sized {
    fn from_arg_bytes(bytes: &[u8]) -> Result<Self>;
    fn to_arg_bytes(&self) -> Result<Vec<u8>>;
}

pub trait NestedArgBytes: Sized {
    fn from_nested_arg_bytes(input: &[u8]) -> Result<Self>;
    fn to_nested_arg_bytes(&self) -> Result<Vec<u8>>;
}

impl NestedArgBytes for () {
    fn from_nested_arg_bytes(input: &[u8]) -> Result<Self> {
        let chunks: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;
        if !chunks.is_empty() {
            bail!("Expected zero args for ()");
        }
        Ok(())
    }
    fn to_nested_arg_bytes(&self) -> Result<Vec<u8>> {
        serialize_to_msgpack_bytes(&Vec::<Vec<u8>>::new())
    }
}

impl<Head, Tail> NestedArgBytes for (Head, Tail)
where
    Head: ArgBytes,
    Tail: NestedArgBytes,
{
    fn from_nested_arg_bytes(input: &[u8]) -> Result<Self> {
        let chunks: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(input)
            .context("Failed to parse input as Vec<Vec<u8>>")?;
        if chunks.is_empty() {
            bail!("Not enough args");
        }
        let head = Head::from_arg_bytes(&chunks[0]).context("Failed to deserialize head")?;
        let tail_packed =
            serialize_to_msgpack_bytes(&chunks[1..]).context("Failed to serialize tail")?;
        let tail =
            Tail::from_nested_arg_bytes(&tail_packed).context("Failed to deserialize tail")?;
        Ok((head, tail))
    }

    fn to_nested_arg_bytes(&self) -> Result<Vec<u8>> {
        let (head, tail) = self;
        let head_bytes = head.to_arg_bytes()?;
        let tail_packed = tail.to_nested_arg_bytes()?;
        let mut chunks: Vec<Vec<u8>> = deserialize_from_msgpack_bytes(&tail_packed)
            .context("Failed to deserialize tail bytes")?;
        chunks.insert(0, head_bytes);
        serialize_to_msgpack_bytes(&chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::bincode::Bincode;
    use crate::serialization::mpk::Msgpack;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: u32,
        name: String,
        active: bool,
    }

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct SerializationTestData {
        id: u32,
        name: String,
    }

    #[test]
    fn test_arg_bytes_msgpack_and_bincode_of_data() {
        let data = SerializationTestData { id: 7, name: "sp1".to_string() };

        let msgpack_bytes = serialize_to_msgpack_bytes(&data).unwrap();
        let Msgpack(parsed): Msgpack<SerializationTestData> =
            ArgBytes::from_arg_bytes(&msgpack_bytes).unwrap();
        assert_eq!(parsed, data);

        let bincode_bytes = serialize_to_bincode_bytes(&data).unwrap();
        let Bincode(parsed): Bincode<SerializationTestData> =
            ArgBytes::from_arg_bytes(&bincode_bytes).unwrap();
        assert_eq!(parsed, data);
    }

    #[test]
    fn test_args_bytes_vec_of_data() {
        let val = SerializationTestData { id: 1, name: "msgpack".into() };

        let chunk = serialize_to_msgpack_bytes(&val).unwrap();
        let one_chunk = serialize_to_msgpack_bytes(&vec![chunk]).unwrap();
        let wrapper: Msgpack<SerializationTestData> =
            NestedArgBytes::from_nested_arg_bytes(&one_chunk).unwrap();
        assert_eq!(wrapper.0, val);

        let chunk = serialize_to_bincode_bytes(&val).unwrap();
        let one_chunk = serialize_to_msgpack_bytes(&vec![chunk]).unwrap();
        let wrapper: Bincode<SerializationTestData> =
            NestedArgBytes::from_nested_arg_bytes(&one_chunk).unwrap();
        assert_eq!(wrapper.0, val);
    }

    #[test]
    fn test_args_bytes_vec_of_two_data() {
        let val1 = SerializationTestData { id: 11, name: "a".into() };
        let val2 = SerializationTestData { id: 22, name: "b".into() };

        let a = serialize_to_msgpack_bytes(&val1).unwrap();
        let b = serialize_to_bincode_bytes(&val2).unwrap();
        let input_chunks = vec![a, b];
        let packed_input = serialize_to_msgpack_bytes(&input_chunks).unwrap();

        let (Msgpack(v1), Bincode(v2)): (
            Msgpack<SerializationTestData>,
            Bincode<SerializationTestData>,
        ) = NestedArgBytes::from_nested_arg_bytes(&packed_input).unwrap();

        assert_eq!(v1, val1);
        assert_eq!(v2, val2);
    }

    #[test]
    fn test_arg_bytes_vec_of_msgpack_and_bincode_of_data() {
        let val1 = SerializationTestData { id: 100, name: "left".into() };
        let val2 = SerializationTestData { id: 200, name: "right".into() };
        let flag = true;

        let chunk1 = serialize_to_bincode_bytes(&val1).unwrap();
        let chunk2 = serialize_to_bincode_bytes(&val2).unwrap();
        let chunk3 = serialize_to_msgpack_bytes(&flag).unwrap();

        let input_chunks = vec![chunk1, chunk2, chunk3];
        let packed_input = serialize_to_msgpack_bytes(&input_chunks).unwrap();

        let (Bincode(left), (Bincode(right), Msgpack(is_set))): (
            Bincode<SerializationTestData>,
            (Bincode<SerializationTestData>, Msgpack<bool>),
        ) = NestedArgBytes::from_nested_arg_bytes(&packed_input).unwrap();

        assert_eq!(left, val1);
        assert_eq!(right, val2);
        assert!(is_set);
    }

    #[test]
    fn test_args_bytes_invalid_format() {
        let not_nested_vec = serialize_to_msgpack_bytes(&"not nested array").unwrap();

        let result: Result<(Msgpack<SerializationTestData>, Bincode<SerializationTestData>)> =
            NestedArgBytes::from_nested_arg_bytes(&not_nested_vec);

        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("Failed to parse input as Vec<Vec<u8>>"));
    }

    #[test]
    fn test_args_bytes_empty_inputs_error() {
        let packed_empty = serialize_to_msgpack_bytes::<Vec<Vec<u8>>>(&vec![]).unwrap();

        let result: Result<(Msgpack<SerializationTestData>, Bincode<SerializationTestData>)> =
            NestedArgBytes::from_nested_arg_bytes(&packed_empty);

        assert!(result.is_err());
        assert!(format!("{:?}", result.unwrap_err()).contains("Not enough args"));
    }

    #[test]
    fn test_args_bytes_rejects_totally_empty_slice() {
        let result: Result<Msgpack<SerializationTestData>> =
            NestedArgBytes::from_nested_arg_bytes(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_arg_bytes_msgpack_and_bincode_of_data() {
        let msgpack_data = SerializationTestData { id: 42, name: "msgpack_test".to_string() };

        let msgpack = Msgpack(msgpack_data);
        let msgpack_bytes = ArgBytes::to_arg_bytes(&msgpack).unwrap();
        let deserialized: SerializationTestData =
            deserialize_from_msgpack_bytes(&msgpack_bytes).unwrap();
        let expected_msgpack = SerializationTestData { id: 42, name: "msgpack_test".to_string() };
        assert_eq!(deserialized, expected_msgpack);

        let bincode_data = SerializationTestData { id: 42, name: "bincode_test".to_string() };
        let bincode = Bincode(bincode_data);
        let bincode_bytes = ArgBytes::to_arg_bytes(&bincode).unwrap();
        let deserialized: SerializationTestData =
            deserialize_from_bincode_bytes(&bincode_bytes).unwrap();
        let expected_bincode = SerializationTestData { id: 42, name: "bincode_test".to_string() };
        assert_eq!(deserialized, expected_bincode);
    }

    #[test]
    fn test_nested_arg_bytes_roundtrip_single_of_data() {
        let data = SerializationTestData { id: 123, name: "single".to_string() };
        let msgpack = Msgpack(data);

        let serialized = NestedArgBytes::to_nested_arg_bytes(&msgpack).unwrap();
        let deserialized: Msgpack<SerializationTestData> =
            NestedArgBytes::from_nested_arg_bytes(&serialized).unwrap();
        let expected = SerializationTestData { id: 123, name: "single".to_string() };
        assert_eq!(deserialized.0, expected);
    }

    #[test]
    fn test_nested_arg_bytes_roundtrip_tuple_two_of_data() {
        let data1 = SerializationTestData { id: 1, name: "first".to_string() };
        let data2 = SerializationTestData { id: 2, name: "second".to_string() };

        let tuple = (Msgpack(data1), Bincode(data2));
        let serialized = NestedArgBytes::to_nested_arg_bytes(&tuple).unwrap();

        let deserialized: (Msgpack<SerializationTestData>, Bincode<SerializationTestData>) =
            NestedArgBytes::from_nested_arg_bytes(&serialized).unwrap();

        let expected1 = SerializationTestData { id: 1, name: "first".to_string() };
        let expected2 = SerializationTestData { id: 2, name: "second".to_string() };
        assert_eq!(deserialized.0.0, expected1);
        assert_eq!(deserialized.1.0, expected2);
    }

    #[test]
    fn test_nested_arg_bytes_roundtrip_nested_tuple_of_data() {
        let data1 = SerializationTestData { id: 10, name: "left".to_string() };
        let data2 = SerializationTestData { id: 20, name: "right".to_string() };
        let flag = false;

        let nested = (Bincode(data1), (Msgpack(data2), Bincode(flag)));
        let serialized = NestedArgBytes::to_nested_arg_bytes(&nested).unwrap();

        let deserialized: (
            Bincode<SerializationTestData>,
            (Msgpack<SerializationTestData>, Bincode<bool>),
        ) = NestedArgBytes::from_nested_arg_bytes(&serialized).unwrap();

        let expected1 = SerializationTestData { id: 10, name: "left".to_string() };
        let expected2 = SerializationTestData { id: 20, name: "right".to_string() };
        assert_eq!(deserialized.0.0, expected1);
        assert_eq!(deserialized.1.0.0, expected2);
        assert_eq!(deserialized.1.1.0, flag);
    }
}
