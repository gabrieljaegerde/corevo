use std::str::FromStr;
use blake2::{Blake2b512, Digest};
use subxt::OnlineClient;
use subxt_signer::{ExposeSecret, SecretUri};
use subxt_signer::sr25519::Keypair;
use x25519_dalek::{StaticSecret, PublicKey as X25519PublicKey};
use crypto_box::{PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, ChaChaBox, aead::{Aead, AeadCore, OsRng}};
use crate::{assethub, AssetHubConfig, primitives::{VotingAccount}};

pub async fn derive_account(api: &OnlineClient<AssetHubConfig>, secret: &str) -> Result<VotingAccount, Box<dyn std::error::Error>> {
    let uri = SecretUri::from_str(secret)?;
    let sr25519_keypair = Keypair::from_uri(&uri)?;

    // derive X25519 keypair
    let mut hasher = Blake2b512::new();
    hasher.update(uri.phrase.expose_secret().as_bytes());
    if let Some(password) = &uri.password {
        hasher.update(password.expose_secret().as_bytes());
    }
    // Add junctions for derivation path
    for junction in &uri.junctions {
        hasher.update(format!("{:?}", junction).as_bytes());
    }
    let hash = hasher.finalize();

    let x25519_secret = StaticSecret::from(<[u8; 32]>::try_from(&hash[..32]).unwrap());
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // check account on chain
    let account_id = sr25519_keypair.public_key().to_account_id();
    println!("Address for {}: {}", secret, account_id);
    let storage = api.storage().at_latest().await?;
    let account_info = storage
        .fetch(&assethub::storage().system().account(account_id))
        .await?.expect("Account should exist");
    println!("   {} has balance of {:?}", secret, account_info.data.free);
    Ok(VotingAccount { sr25519_keypair, x25519_public, x25519_secret })
}

/// Encrypt 32 bytes for a recipient using their X25519 public key
pub fn encrypt_for_recipient(
    sender_x25519_secret: &StaticSecret,
    recipient_x25519_public: &X25519PublicKey,
    plaintext: &Vec<u8>,
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    let their_box_public = BoxPublicKey::from(*recipient_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(sender_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    let nonce = ChaChaBox::generate_nonce(&mut OsRng);
    let ciphertext = crypto_box.encrypt(&nonce, plaintext.as_ref())?;

    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt message from sender using their X25519 public key
pub fn decrypt_from_sender(
    recipient_x25519_secret: &StaticSecret,
    sender_x25519_public: &X25519PublicKey,
    ciphertext: &[u8],
) -> Result<Vec<u8>, crypto_box::aead::Error> {
    // Extract nonce (first 24 bytes) and ciphertext (rest)
    if ciphertext.len() < 24 {
        return Err(crypto_box::aead::Error);
    }

    let (nonce_bytes, encrypted_data) = ciphertext.split_at(24);
    let nonce = crypto_box::Nonce::from_slice(nonce_bytes);

    // Create crypto_box from recipient secret and sender public
    let their_box_public = BoxPublicKey::from(*sender_x25519_public.as_bytes());
    let my_box_secret = BoxSecretKey::from(recipient_x25519_secret.to_bytes());
    let crypto_box = ChaChaBox::new(&their_box_public, &my_box_secret);

    // Decrypt
    let plaintext = crypto_box.decrypt(nonce, encrypted_data)?;
    Ok(plaintext)
}
