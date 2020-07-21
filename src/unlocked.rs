use super::locked::LockedWallet;
use contents::Content;

pub struct UnlockedWallet {
    pub context: Vec<String>,
    pub id: String,
    pub wallet_type: Vec<String>,
    contents: HashSet<Content>,
}

pub impl UnlockedWallet {
    pub fn sign_raw(&self, data: &[u8], key_ref: &str) -> Result<Vec<u8>, 'str> {
        match self.get_content(key_ref) {
            Some(c) => match c {
                Content::Key(k) => k.sign(data),
                _ => Err("incorrect content type"),
            },
            None => Err("no key found"),
        }
    }
    pub fn verify_raw(&self, data: &[u8], key_ref: &str, signature: &[u8]) -> Result<(), 'str> {
        match self.get_content(key_ref) {
            Some(c) => match c {
                Content::Key(k) => k.verify(data, signature),
                _ => Err("incorrect content type"),
            },
            None => Err("no key found"),
        }
    }
    pub fn decrypt(&self, data: &[u8], key_ref: &str) -> Result<Vec<u8>, 'str> {
        match self.get_content(key_ref) {
            Some(c) => match c {
                Content::Key(k) => k.decrypt(data, signature),
                _ => Err("incorrect content type"),
            },
            None => Err("no key found"),
        }
    }
    pub fn get_dids(&self) -> Vec<String> {
        self.content.iter().filter(|c| match c {
            Content::Profile(_) => true,
            _ => false,
        })
    }
    pub fn lock(&self, key: &[u8]) -> Result<LockedWallet, 'str> {
        todo!()
    }

    fn get_content(&self, c_ref: &str) -> Option<Content> {
        self.content.iter().find(|c| c_ref == c.id())
    }
}
