use super::unlocked::UnlockedWallet;

pub struct LockedWallet {
    encrypted_data: Vec<u8>,
}

impl LockedWallet {
    pub fn unlock(&self, key: &[u8]) -> Result<UnlockedWallet, 'str> {}
}
