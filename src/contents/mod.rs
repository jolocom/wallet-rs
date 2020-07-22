pub mod entropy;
pub mod key;

pub enum Content {
    Entropy(entropy::Entropy),
    Key(key::Key),
}

impl Content {
    fn id(&self) -> &str {
        match self {
            Self::Profile(p) => p.id,
            Self::Key(k) => k.id,
            Self::Entropy(e) => e.id,
        }
    }
}
