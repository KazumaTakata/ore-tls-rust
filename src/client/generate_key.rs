use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use x509_parser::nom::AsBytes;

const key_length: i32 = 32;

const master_secret_length: usize = 48;

type HmacSha256 = Hmac<Sha256>;

fn generate_pre_master_sercret(partner_public_key: [u8; 32]) -> SharedSecret {
    let alice_secret = EphemeralSecret::random_from_rng(OsRng);
    let alice_public = PublicKey::from(&alice_secret);
    let partner_public_key = PublicKey::from(partner_public_key);
    let shared_secret = alice_secret.diffie_hellman(&partner_public_key);
    return shared_secret;
}

fn generate_key_block(
    pre_master_secret: &[u8],
    client_random: [u8; 32],
    server_random: [u8; 32],
) -> Vec<u8> {
    let client_random_and_server_random = [client_random, server_random].concat();
    let master_secret = PRF(
        pre_master_secret,
        &client_random_and_server_random,
        "master secret",
    );

    let client_random_and_server_random = [server_random, client_random].concat();
    let key_block = PRF(
        master_secret.as_bytes(),
        &client_random_and_server_random,
        "key expansion",
    );

    // https://cs.opensource.google/go/go/+/master:src/crypto/tls/prf.go;l=140?q=%22master%20secret%22&ss=go%2Fgo
    // https://cs.opensource.google/go/go/+/master:src/crypto/tls/cipher_suites.go;l=68;drc=856a7bc8e975d29b7c221264f8b0c62df2d60e42

    return master_secret;
}

fn PRF(pre_master_secret: &[u8], seed: &[u8], label: &str) -> Vec<u8> {
    let mut label_and_seed = vec![];
    label_and_seed.extend_from_slice(label.as_bytes());
    label_and_seed.extend_from_slice(&seed);

    let result = p_hash(pre_master_secret, &label_and_seed);
    return result;
}

fn p_hash(secret: &[u8], seed: &[u8]) -> Vec<u8> {
    let mut result = vec![];
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(seed.as_bytes());
    let mut a = mac.finalize().into_bytes();

    let mut result_length: usize = 0;

    while result_length < master_secret_length {
        mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(a.as_bytes());
        mac.update(seed.as_bytes());
        let b = mac.finalize().into_bytes();
        result.extend_from_slice(&b);
        result_length += b.len();
        mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(a.as_bytes());
        a = mac.finalize().into_bytes();
    }

    return result[0..master_secret_length].to_vec();
}
