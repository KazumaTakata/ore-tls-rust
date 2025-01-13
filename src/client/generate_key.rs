use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use x509_parser::nom::AsBytes;

const key_length: i32 = 32;

const master_secret_length: usize = 48;

type HmacSha256 = Hmac<Sha256>;

fn generate_pre_master_sercret(partner_public_key: [u8; 32]) -> (SharedSecret, PublicKey) {
    let my_secret_key = EphemeralSecret::random_from_rng(OsRng);
    let my_public_key = PublicKey::from(&my_secret_key);
    let partner_public_key: PublicKey = PublicKey::from(partner_public_key);
    let shared_secret = my_secret_key.diffie_hellman(&partner_public_key);
    return (shared_secret, my_public_key);
}

pub fn key_exchange(
    partner_public_key: [u8; 32],
    client_random: [u8; 32],
    server_random: [u8; 32],
) {
    let (pre_master_secret, my_public_key) = generate_pre_master_sercret(partner_public_key);
    println!(
        "pre_master_secret: {:?}",
        pre_master_secret.as_bytes().len()
    );
    let byte_pre_master_secret = pre_master_secret.as_bytes();
    let block = generate_key_block(byte_pre_master_secret, client_random, server_random);
}

fn generate_key_block(
    pre_master_secret: &[u8; 32],
    client_random: [u8; 32],
    server_random: [u8; 32],
) -> Vec<u8> {
    let client_random_and_server_random = [client_random, server_random].concat();
    let master_secret = PRF(
        pre_master_secret,
        &client_random_and_server_random,
        "master secret",
        master_secret_length,
    );

    let master_secret_bytes = master_secret.as_bytes();

    println!("master_secret_length: {:?}", master_secret_bytes.len());

    let client_random_and_server_random = [server_random, client_random].concat();
    let key_block = PRF(
        master_secret.as_bytes(),
        &client_random_and_server_random,
        "key expansion",
        40,
    );

    // https://cs.opensource.google/go/go/+/master:src/crypto/tls/prf.go;l=140?q=%22master%20secret%22&ss=go%2Fgo
    // https://cs.opensource.google/go/go/+/master:src/crypto/tls/cipher_suites.go;l=154;drc=856a7bc8e975d29b7c221264f8b0c62df2d60e42

    let client_key = key_block[0..16 as usize].to_vec();
    let server_key = key_block[16..32 as usize].to_vec();
    let client_iv = key_block[32..36 as usize].to_vec();
    let server_iv = key_block[36..40 as usize].to_vec();

    return master_secret;
}

pub fn PRF(pre_master_secret: &[u8], seed: &[u8], label: &str, length: usize) -> Vec<u8> {
    let mut label_and_seed = vec![];
    label_and_seed.extend_from_slice(label.as_bytes());
    label_and_seed.extend_from_slice(&seed);
    let result = p_hash(pre_master_secret, &label_and_seed);
    return result[0..length].to_vec();
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

    return result;
}
