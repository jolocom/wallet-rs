use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq)]
pub struct Entropy {
    pub entropy_type: Vec<String>,
    value: Vec<u8>,
}
