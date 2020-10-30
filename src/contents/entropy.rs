use serde::{
    Deserialize,
    Serialize
};
use wasm_bindgen::prelude::*;

/// Entropy type for JSON serialization
#[wasm_bindgen]
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Entropy {
    #[serde(rename = "type")]
    pub entropy_type: Box<[JsValue]>,
    #[serde(with = "serde_base_64")]
    value: Vec<u8>,
}

mod serde_base_64 {
    use base64;
    use serde::{de, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(t: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&base64::encode_config(t, base64::URL_SAFE))
    }
    pub fn deserialize<'a, D: Deserializer<'a>>(der: D) -> Result<Vec<u8>, D::Error> {
        struct Base64Visitor;

        impl<'a> de::Visitor<'a> for Base64Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                formatter.write_str("expected base64 encoded value")
            }

            fn visit_str<E>(self, b64_encoded_str: &str) -> Result<Vec<u8>, E>
            where
                E: serde::de::Error,
            {
                base64::decode_config(b64_encoded_str, base64::URL_SAFE).map_err(de::Error::custom)
            }
        }

        der.deserialize_string(Base64Visitor)
    }
}
