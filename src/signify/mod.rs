use base64::{Engine, prelude::BASE64_STANDARD};
use ed25519_dalek::ed25519::signature::SignerMut;
use sha2::Digest;

#[derive(Debug)]
struct SecretKey {
    alg: String,
    kdf: String,
    rounds: u32,
    salt: [u8; 16],
    checksum: [u8; 8],
    keynum: [u8; 8],
    key: [u8; 64]
}

pub fn sign_native(data: &[u8]) -> Vec<u8> {
    let raw_key = BASE64_STANDARD.decode("RWRCSwAAAABPaA4AvTHxK+mZsvLFhQL8VVCYmBWQ19q5ZkPQug0LNYz7yqD5w+Cyi9MHaPOUmaqTLMW/spAB7HQ8bgHY6RTee4do/wb14BA4hqSVJ3ZDBtvHqOKoxVfrFRALT7NqNiw=").unwrap();
    let key = SecretKey {
        alg: raw_key[0..2].as_ascii().unwrap().as_str().to_string(),
        kdf: raw_key[2..4].as_ascii().unwrap().as_str().to_string(),
        rounds: u32::from_le_bytes(raw_key[4..8].try_into().unwrap()),
        salt: raw_key[8..24].try_into().unwrap(),
        checksum: raw_key[24..32].try_into().unwrap(),
        keynum: raw_key[32..40].try_into().unwrap(),
        key: raw_key[40..104].try_into().unwrap()
    };

    let checksum = {
        let mut sha = sha2::Sha512::new();
        sha.update(key.key);
        sha.finalize()
    }.to_vec();

    // only compare as many bytes as are in the deserialized checksum (usually 8)
    for i in 0..key.checksum.len() {
        if key.checksum[i] != checksum[i] {
            panic!("Key checksum mismatch");
        }
    }

    let mut secret_key = ed25519_dalek::SigningKey::from_keypair_bytes(&key.key).expect("Can't load secret key");
    let mut sig = secret_key.sign(data).to_vec();

    let mut full_signature: Vec<u8> = "Ed".as_bytes().to_vec();
    full_signature.append(&mut key.keynum.to_vec());
    full_signature.append(&mut sig);

    full_signature
}