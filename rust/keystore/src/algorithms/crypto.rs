use alloc::vec::Vec;
use cryptoxide::{hmac::Hmac, mac::Mac, pbkdf2::pbkdf2, sha2::Sha256, sha2::Sha512};

/// BIP39: seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, 2048 iterations).
pub fn bip39_mnemonic_to_seed(mnemonic: &str, passphrase: &[u8]) -> [u8; 64] {
    let salt: Vec<u8> = ["mnemonic".as_bytes(), passphrase].concat();
    let mut seed = [0u8; 64];
    pbkdf2(
        &mut Hmac::new(Sha512::new(), mnemonic.as_bytes()),
        &salt,
        2048,
        &mut seed,
    );
    seed
}

pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let digest = cryptoxide::sha2::Sha512::new();
    let mut hmac = cryptoxide::hmac::Hmac::new(digest, key);
    hmac.input(data);
    let mut output = [0u8; 64];
    hmac.raw_result(&mut output);
    output
}

pub fn hkdf(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut output = [0u8; 32];
    pbkdf2(
        &mut Hmac::new(Sha256::new(), password),
        salt,
        iterations,
        &mut output,
    );
    output
}

pub fn hkdf64(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 64] {
    let mut output = [0u8; 64];
    pbkdf2(
        &mut Hmac::new(Sha256::new(), password),
        salt,
        iterations,
        &mut output,
    );
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use hex;

    #[test]
    fn test_bip39_mnemonic_to_seed() {
        // Trezor BIP39 reference vector (entropy 0x00*16, passphrase "TREZOR").
        let seed = bip39_mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            b"TREZOR",
        );
        assert_eq!(
            hex::encode(seed),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn test_hkdf_should_work() {
        let password = [0u8; 32];
        let salt = [1u8; 32];
        let result = hkdf(&password, &salt, 700);

        let result_string = hex::encode(result);
        let expected =
            "6aefec5dba55456b76af351156665c5e4e0939d09426dff80f93e0960ba2fbd0".to_string();
        assert_eq!(result_string, expected);
    }
}
