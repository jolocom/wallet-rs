pub mod entropy;
pub mod key;
pub mod profile;

pub enum Content {
    Entropy(entropy::Entropy),
    Key(key::Key),
    Profile(profile::Profile),
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
