use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};
use hartevo_domain_kernel::{
    DeviceHandoffCiphertext, DeviceHandoffContext, DeviceKeyAgreementAlgorithm, KeyRecipient,
    KeyWrapAlgorithm, ProjectId, TenantId, WrappedKeyCiphertext,
};
use keyring_core::{Entry, Error as KeyringError};
use ring::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf::{HKDF_SHA256, KeyType, Salt};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const MAX_CONTENT_BYTES: usize = 16 * 1024 * 1024 - 16;
const BROWSER_RECIPE_AUTHORITY_PROVIDER: &str = "hartevo-browser-recipe-authority";
const BROWSER_RECIPE_ROOT_SIGNING_PURPOSE: &str = "ed25519-root-signing-key";
static NATIVE_STORE_READY: OnceLock<Result<(), ()>> = OnceLock::new();

pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Result<Self, SecretStoreError> {
        if bytes.is_empty() {
            return Err(SecretStoreError::InvalidSecret);
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretBytes")
            .field("value", &"[REDACTED]")
            .field("length", &self.0.len())
            .finish()
    }
}

pub struct KeyMaterial([u8; KEY_BYTES]);

impl KeyMaterial {
    pub fn generate() -> Result<Self, SecretStoreError> {
        let mut bytes = [0_u8; KEY_BYTES];
        SystemRandom::new()
            .fill(&mut bytes)
            .map_err(|_| SecretStoreError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Result<Self, SecretStoreError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(SecretStoreError::InvalidSecret);
        }
        Ok(Self(bytes))
    }

    pub fn from_secret(secret: &SecretBytes) -> Result<Self, SecretStoreError> {
        let bytes: [u8; KEY_BYTES] = secret
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::InvalidSecret)?;
        Self::from_bytes(bytes)
    }

    pub fn to_secret(&self) -> SecretBytes {
        SecretBytes(Zeroizing::new(self.0.to_vec()))
    }

    fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for KeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyMaterial([REDACTED])")
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvelopeContext {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub key_version: u64,
    pub recipient: KeyRecipient,
    pub purpose: String,
    pub expires_at: Option<DateTime<Utc>>,
}

impl EnvelopeContext {
    fn canonical_aad(&self) -> Result<Vec<u8>, SecretStoreError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.key_version == 0
            || self.purpose.trim().is_empty()
        {
            return Err(SecretStoreError::InvalidEnvelopeContext);
        }
        Ok(serde_json::to_vec(self)?)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct EnvelopeCrypto;

impl EnvelopeCrypto {
    pub fn seal_key(
        project_key: &KeyMaterial,
        wrapping_key: &KeyMaterial,
        context: &EnvelopeContext,
    ) -> Result<WrappedKeyCiphertext, SecretStoreError> {
        let aad = context.canonical_aad()?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SecretStoreError::RandomnessUnavailable)?;
        let key = aead_key(wrapping_key)?;
        let mut ciphertext = project_key.as_bytes().to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad.as_slice()),
            &mut ciphertext,
        )
        .map_err(|_| SecretStoreError::EncryptionFailed)?;
        Ok(WrappedKeyCiphertext {
            algorithm: KeyWrapAlgorithm::Aes256GcmV1,
            nonce: nonce.to_vec(),
            ciphertext,
            aad_digest: format!("{:x}", Sha256::digest(&aad)),
        })
    }

    pub fn open_key(
        sealed: &WrappedKeyCiphertext,
        wrapping_key: &KeyMaterial,
        context: &EnvelopeContext,
    ) -> Result<KeyMaterial, SecretStoreError> {
        if !sealed.validate() || sealed.algorithm != KeyWrapAlgorithm::Aes256GcmV1 {
            return Err(SecretStoreError::InvalidCiphertext);
        }
        let aad = context.canonical_aad()?;
        if sealed.aad_digest != format!("{:x}", Sha256::digest(&aad)) {
            return Err(SecretStoreError::EnvelopeScopeMismatch);
        }
        let nonce: [u8; NONCE_BYTES] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let mut ciphertext = Zeroizing::new(sealed.ciphertext.clone());
        let plaintext = aead_key(wrapping_key)?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        let key_bytes: [u8; KEY_BYTES] = plaintext
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        KeyMaterial::from_bytes(key_bytes)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DeviceKeyAgreementCrypto;

impl DeviceKeyAgreementCrypto {
    pub fn generate_private_key() -> Result<KeyMaterial, SecretStoreError> {
        KeyMaterial::generate()
    }

    pub fn public_key(private_key: &KeyMaterial) -> Vec<u8> {
        let private = X25519StaticSecret::from(*private_key.as_bytes());
        X25519PublicKey::from(&private).as_bytes().to_vec()
    }

    pub fn public_key_digest(public_key: &[u8]) -> Result<String, SecretStoreError> {
        validate_x25519_public_key(public_key)?;
        Ok(format!("{:x}", Sha256::digest(public_key)))
    }

    pub fn seal_project_key(
        project_key: &KeyMaterial,
        target_public_key: &[u8],
        context: &DeviceHandoffContext,
    ) -> Result<DeviceHandoffCiphertext, SecretStoreError> {
        let aad = handoff_aad(context)?;
        if Self::public_key_digest(target_public_key)? != context.target_public_key_digest {
            return Err(SecretStoreError::EnvelopeScopeMismatch);
        }
        let target_public_key: [u8; KEY_BYTES] = target_public_key
            .try_into()
            .map_err(|_| SecretStoreError::InvalidPublicKey)?;
        let target_public = X25519PublicKey::from(target_public_key);

        let mut ephemeral_bytes = [0_u8; KEY_BYTES];
        SystemRandom::new()
            .fill(&mut ephemeral_bytes)
            .map_err(|_| SecretStoreError::RandomnessUnavailable)?;
        let ephemeral_private = X25519StaticSecret::from(ephemeral_bytes);
        ephemeral_bytes.zeroize();
        let ephemeral_public = X25519PublicKey::from(&ephemeral_private);
        let shared_secret = ephemeral_private.diffie_hellman(&target_public);
        reject_non_contributory_shared_secret(shared_secret.as_bytes())?;

        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SecretStoreError::RandomnessUnavailable)?;
        let mut ciphertext = project_key.as_bytes().to_vec();
        handoff_aead_key(shared_secret.as_bytes(), &aad)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| SecretStoreError::EncryptionFailed)?;

        Ok(DeviceHandoffCiphertext {
            algorithm: DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1,
            sender_ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
            nonce: nonce.to_vec(),
            content_digest: format!("{:x}", Sha256::digest(&ciphertext)),
            ciphertext,
            aad_digest: format!("{:x}", Sha256::digest(&aad)),
        })
    }

    pub fn open_project_key(
        sealed: &DeviceHandoffCiphertext,
        target_private_key: &KeyMaterial,
        context: &DeviceHandoffContext,
    ) -> Result<KeyMaterial, SecretStoreError> {
        if !sealed.validate()
            || sealed.algorithm != DeviceKeyAgreementAlgorithm::X25519HkdfSha256Aes256GcmV1
        {
            return Err(SecretStoreError::InvalidCiphertext);
        }
        let aad = handoff_aad(context)?;
        if sealed.aad_digest != format!("{:x}", Sha256::digest(&aad))
            || Self::public_key_digest(&Self::public_key(target_private_key))?
                != context.target_public_key_digest
        {
            return Err(SecretStoreError::EnvelopeScopeMismatch);
        }
        let ephemeral_public: [u8; KEY_BYTES] = sealed
            .sender_ephemeral_public_key
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let target_private = X25519StaticSecret::from(*target_private_key.as_bytes());
        let shared_secret = target_private.diffie_hellman(&X25519PublicKey::from(ephemeral_public));
        reject_non_contributory_shared_secret(shared_secret.as_bytes())?;
        let nonce: [u8; NONCE_BYTES] = sealed
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let mut ciphertext = Zeroizing::new(sealed.ciphertext.clone());
        let plaintext = handoff_aead_key(shared_secret.as_bytes(), &aad)?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        let key_bytes: [u8; KEY_BYTES] = plaintext
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        KeyMaterial::from_bytes(key_bytes)
    }
}

#[derive(Clone, Copy, Debug)]
struct Aes256KeyLength;

impl KeyType for Aes256KeyLength {
    fn len(&self) -> usize {
        KEY_BYTES
    }
}

fn handoff_aad(context: &DeviceHandoffContext) -> Result<Vec<u8>, SecretStoreError> {
    context
        .validate()
        .map_err(|_| SecretStoreError::InvalidHandoffContext)?;
    serde_json::to_vec(context).map_err(SecretStoreError::from)
}

fn handoff_aead_key(
    shared_secret: &[u8; KEY_BYTES],
    aad: &[u8],
) -> Result<LessSafeKey, SecretStoreError> {
    let salt = Salt::new(HKDF_SHA256, b"hartevo-device-handoff-v1");
    let pseudo_random_key = salt.extract(shared_secret);
    let info = [b"x25519-hkdf-sha256-aes256gcm-v1".as_slice(), aad];
    let output_key_material = pseudo_random_key
        .expand(&info, Aes256KeyLength)
        .map_err(|_| SecretStoreError::KeyDerivationFailed)?;
    let mut derived_key = [0_u8; KEY_BYTES];
    output_key_material
        .fill(&mut derived_key)
        .map_err(|_| SecretStoreError::KeyDerivationFailed)?;
    let unbound = UnboundKey::new(&AES_256_GCM, &derived_key)
        .map_err(|_| SecretStoreError::KeyDerivationFailed)?;
    derived_key.zeroize();
    Ok(LessSafeKey::new(unbound))
}

fn validate_x25519_public_key(public_key: &[u8]) -> Result<(), SecretStoreError> {
    if public_key.len() != KEY_BYTES || public_key.iter().all(|byte| *byte == 0) {
        return Err(SecretStoreError::InvalidPublicKey);
    }
    Ok(())
}

fn reject_non_contributory_shared_secret(
    shared_secret: &[u8; KEY_BYTES],
) -> Result<(), SecretStoreError> {
    if shared_secret.iter().all(|byte| *byte == 0) {
        return Err(SecretStoreError::InvalidPublicKey);
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentEncryptionContext {
    pub cell: String,
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub object_id: String,
    pub object_kind: String,
    pub object_revision: u64,
    pub key_version: u64,
    pub tombstone: bool,
}

impl ContentEncryptionContext {
    fn canonical_aad(&self) -> Result<Vec<u8>, SecretStoreError> {
        if self.cell.trim().is_empty()
            || self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.object_id.trim().is_empty()
            || self.object_kind.trim().is_empty()
            || self.object_revision == 0
            || self.key_version == 0
        {
            return Err(SecretStoreError::InvalidContentContext);
        }
        Ok(serde_json::to_vec(self)?)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedContent {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub aad_digest: String,
    pub content_digest: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContentCrypto;

impl ContentCrypto {
    pub fn intent_digest(
        plaintext: &[u8],
        project_key: &KeyMaterial,
        context: &ContentEncryptionContext,
    ) -> Result<String, SecretStoreError> {
        if plaintext.is_empty() {
            return Err(SecretStoreError::InvalidSecret);
        }
        if plaintext.len() > MAX_CONTENT_BYTES {
            return Err(SecretStoreError::ContentTooLarge);
        }
        let mut canonical = context.canonical_aad()?;
        canonical.extend_from_slice(plaintext);
        let key = hmac::Key::new(hmac::HMAC_SHA256, project_key.as_bytes());
        Ok(hex::encode(hmac::sign(&key, &canonical).as_ref()))
    }

    pub fn seal(
        plaintext: &[u8],
        project_key: &KeyMaterial,
        context: &ContentEncryptionContext,
    ) -> Result<EncryptedContent, SecretStoreError> {
        if plaintext.is_empty() {
            return Err(SecretStoreError::InvalidSecret);
        }
        if plaintext.len() > MAX_CONTENT_BYTES {
            return Err(SecretStoreError::ContentTooLarge);
        }
        let aad = context.canonical_aad()?;
        let mut nonce = [0_u8; NONCE_BYTES];
        SystemRandom::new()
            .fill(&mut nonce)
            .map_err(|_| SecretStoreError::RandomnessUnavailable)?;
        let mut ciphertext = plaintext.to_vec();
        aead_key(project_key)?
            .seal_in_place_append_tag(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                &mut ciphertext,
            )
            .map_err(|_| SecretStoreError::EncryptionFailed)?;
        Ok(EncryptedContent {
            nonce: nonce.to_vec(),
            content_digest: format!("{:x}", Sha256::digest(&ciphertext)),
            ciphertext,
            aad_digest: format!("{:x}", Sha256::digest(&aad)),
        })
    }

    pub fn open(
        encrypted: &EncryptedContent,
        project_key: &KeyMaterial,
        context: &ContentEncryptionContext,
    ) -> Result<SecretBytes, SecretStoreError> {
        if encrypted.nonce.len() != NONCE_BYTES
            || !(16..=MAX_CONTENT_BYTES + 16).contains(&encrypted.ciphertext.len())
            || encrypted.content_digest != format!("{:x}", Sha256::digest(&encrypted.ciphertext))
        {
            return Err(SecretStoreError::InvalidCiphertext);
        }
        let aad = context.canonical_aad()?;
        if encrypted.aad_digest != format!("{:x}", Sha256::digest(&aad)) {
            return Err(SecretStoreError::EnvelopeScopeMismatch);
        }
        let nonce: [u8; NONCE_BYTES] = encrypted
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| SecretStoreError::InvalidCiphertext)?;
        let mut ciphertext = Zeroizing::new(encrypted.ciphertext.clone());
        let plaintext = aead_key(project_key)?
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(aad.as_slice()),
                ciphertext.as_mut_slice(),
            )
            .map_err(|_| SecretStoreError::AuthenticationFailed)?;
        SecretBytes::new(plaintext.to_vec())
    }
}

fn aead_key(key: &KeyMaterial) -> Result<LessSafeKey, SecretStoreError> {
    UnboundKey::new(&AES_256_GCM, key.as_bytes())
        .map(LessSafeKey::new)
        .map_err(|_| SecretStoreError::InvalidSecret)
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretReference {
    pub tenant_id: TenantId,
    pub project_id: ProjectId,
    pub provider: String,
    pub account_scope: String,
    pub purpose: String,
    pub version: u64,
}

impl SecretReference {
    /// Creates the opaque OS-store reference for one Recipe root signing-key
    /// generation. Only scope and generation enter the reference; private key
    /// bytes remain exclusively in the selected [`SecretStore`] backend.
    pub fn browser_recipe_root_signing_key(
        tenant_id: TenantId,
        project_id: ProjectId,
        root_key_id: &str,
        generation: u64,
    ) -> Result<Self, SecretStoreError> {
        if root_key_id.is_empty()
            || root_key_id.len() > 1_024
            || root_key_id != root_key_id.trim()
            || root_key_id.chars().any(char::is_control)
            || generation == 0
        {
            return Err(SecretStoreError::InvalidReference);
        }
        let reference = Self {
            tenant_id,
            project_id,
            provider: BROWSER_RECIPE_AUTHORITY_PROVIDER.into(),
            account_scope: format!("root-key:{root_key_id}"),
            purpose: BROWSER_RECIPE_ROOT_SIGNING_PURPOSE.into(),
            version: generation,
        };
        reference.credential_id()?;
        Ok(reference)
    }

    pub fn credential_id(&self) -> Result<String, SecretStoreError> {
        if self.tenant_id.as_str().trim().is_empty()
            || self.project_id.as_str().trim().is_empty()
            || self.provider.trim().is_empty()
            || self.account_scope.trim().is_empty()
            || self.purpose.trim().is_empty()
            || self.version == 0
        {
            return Err(SecretStoreError::InvalidReference);
        }
        Ok(format!("{:x}", Sha256::digest(serde_json::to_vec(self)?)))
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("credential_id", &self.credential_id().ok())
            .finish()
    }
}

pub trait SecretStore: fmt::Debug + Send + Sync {
    fn put(
        &self,
        reference: &SecretReference,
        secret: &SecretBytes,
    ) -> Result<(), SecretStoreError>;

    fn get(&self, reference: &SecretReference) -> Result<SecretBytes, SecretStoreError>;

    fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError>;
}

#[derive(Clone, Debug)]
pub struct OsSecretStore {
    service: String,
}

impl OsSecretStore {
    pub fn new(service: impl Into<String>) -> Result<Self, SecretStoreError> {
        let service = service.into().trim().to_owned();
        if service.is_empty() {
            return Err(SecretStoreError::InvalidReference);
        }
        if NATIVE_STORE_READY
            .get_or_init(|| initialize_native_store().map_err(|_| ()))
            .is_err()
        {
            return Err(SecretStoreError::BackendUnavailable);
        }
        Ok(Self { service })
    }

    #[cfg(target_os = "macos")]
    fn entry(&self, reference: &SecretReference) -> Result<Entry, SecretStoreError> {
        use apple_native_keyring_store::protected::{AccessPolicy, Cred};

        // Apple recommends the Data Protection Keychain for modern macOS
        // SecItem operations. The device-only policy prevents iCloud or
        // backup migration of Hartevo's local wrapping material.
        Cred::build(
            &self.service,
            &reference.credential_id()?,
            AccessPolicy::WhenUnlockedThisDeviceOnly,
            None,
            false,
        )
        .map_err(|_| SecretStoreError::BackendUnavailable)
    }

    #[cfg(not(target_os = "macos"))]
    fn entry(&self, reference: &SecretReference) -> Result<Entry, SecretStoreError> {
        Entry::new(&self.service, &reference.credential_id()?)
            .map_err(|_| SecretStoreError::BackendUnavailable)
    }

    #[cfg(target_os = "macos")]
    fn legacy_entry(&self, reference: &SecretReference) -> Result<Entry, SecretStoreError> {
        use apple_native_keyring_store::keychain::{Cred, MacKeychainDomain};

        Cred::build(
            MacKeychainDomain::User,
            &self.service,
            &reference.credential_id()?,
        )
        .map_err(|_| SecretStoreError::BackendUnavailable)
    }
}

fn initialize_native_store() -> Result<(), SecretStoreError> {
    #[cfg(target_os = "macos")]
    apple_native_keyring_store::protected::Store::new()
        .map_err(|_| SecretStoreError::BackendUnavailable)?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()
        .map_err(|_| SecretStoreError::BackendUnavailable)?;
    #[cfg(target_os = "linux")]
    let store = linux_keyutils_keyring_store::Store::new()
        .map_err(|_| SecretStoreError::BackendUnavailable)?;
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    return Err(SecretStoreError::BackendUnavailable);
    #[cfg(any(target_os = "windows", target_os = "linux"))]
    {
        keyring_core::set_default_store(store);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn read_secret(entry: &Entry) -> Result<SecretBytes, SecretStoreError> {
    let secret = entry.get_secret().map_err(|error| match error {
        KeyringError::NoEntry => SecretStoreError::SecretNotFound,
        _ => SecretStoreError::BackendUnavailable,
    })?;
    SecretBytes::new(secret)
}

#[cfg(target_os = "macos")]
fn delete_secret(entry: &Entry) -> Result<(), SecretStoreError> {
    entry.delete_credential().map_err(|error| match error {
        KeyringError::NoEntry => SecretStoreError::SecretNotFound,
        _ => SecretStoreError::BackendUnavailable,
    })
}

#[cfg(target_os = "macos")]
fn missing_data_protection_entitlement(error: &KeyringError) -> bool {
    let KeyringError::PlatformFailure(platform_error) = error else {
        return false;
    };
    platform_error
        .downcast_ref::<security_framework::base::Error>()
        .is_some_and(|error| error.code() == -34_018)
}

#[cfg(target_os = "macos")]
fn may_use_legacy_keychain(error: &KeyringError) -> bool {
    // A missing protected item can be a pre-migration legacy item. An
    // unsigned debug host has no protected-keychain entitlement, so debug
    // builds may use the legacy store. Release builds never downgrade on a
    // missing entitlement; every other protected-store failure also remains
    // fail-closed.
    matches!(error, KeyringError::NoEntry)
        || (cfg!(debug_assertions) && missing_data_protection_entitlement(error))
}

impl SecretStore for OsSecretStore {
    fn put(
        &self,
        reference: &SecretReference,
        secret: &SecretBytes,
    ) -> Result<(), SecretStoreError> {
        let primary = self.entry(reference)?;
        match primary.set_secret(secret.as_slice()) {
            Ok(()) => Ok(()),
            #[cfg(target_os = "macos")]
            Err(error) if may_use_legacy_keychain(&error) => self
                .legacy_entry(reference)?
                .set_secret(secret.as_slice())
                .map_err(|_| SecretStoreError::BackendUnavailable),
            Err(_) => Err(SecretStoreError::BackendUnavailable),
        }
    }

    fn get(&self, reference: &SecretReference) -> Result<SecretBytes, SecretStoreError> {
        let primary = self.entry(reference)?;
        match primary.get_secret() {
            Ok(secret) => SecretBytes::new(secret),
            #[cfg(target_os = "macos")]
            Err(error) if may_use_legacy_keychain(&error) => {
                read_secret(&self.legacy_entry(reference)?)
            }
            Err(KeyringError::NoEntry) => Err(SecretStoreError::SecretNotFound),
            Err(_) => Err(SecretStoreError::BackendUnavailable),
        }
    }

    fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError> {
        let primary = self.entry(reference)?;
        match primary.delete_credential() {
            Ok(()) => Ok(()),
            #[cfg(target_os = "macos")]
            Err(error) if may_use_legacy_keychain(&error) => {
                delete_secret(&self.legacy_entry(reference)?)
            }
            Err(KeyringError::NoEntry) => Err(SecretStoreError::SecretNotFound),
            Err(_) => Err(SecretStoreError::BackendUnavailable),
        }
    }
}

#[derive(Debug, Default)]
pub struct MemorySecretStore {
    secrets: Mutex<BTreeMap<String, SecretBytes>>,
}

impl MemorySecretStore {
    pub fn entry_count(&self) -> Result<usize, SecretStoreError> {
        Ok(self
            .secrets
            .lock()
            .map_err(|_| SecretStoreError::BackendUnavailable)?
            .len())
    }
}

impl SecretStore for MemorySecretStore {
    fn put(
        &self,
        reference: &SecretReference,
        secret: &SecretBytes,
    ) -> Result<(), SecretStoreError> {
        self.secrets
            .lock()
            .map_err(|_| SecretStoreError::BackendUnavailable)?
            .insert(
                reference.credential_id()?,
                SecretBytes::new(secret.as_slice().to_vec())?,
            );
        Ok(())
    }

    fn get(&self, reference: &SecretReference) -> Result<SecretBytes, SecretStoreError> {
        self.secrets
            .lock()
            .map_err(|_| SecretStoreError::BackendUnavailable)?
            .get(&reference.credential_id()?)
            .map(|secret| SecretBytes::new(secret.as_slice().to_vec()))
            .transpose()?
            .ok_or(SecretStoreError::SecretNotFound)
    }

    fn delete(&self, reference: &SecretReference) -> Result<(), SecretStoreError> {
        self.secrets
            .lock()
            .map_err(|_| SecretStoreError::BackendUnavailable)?
            .remove(&reference.credential_id()?)
            .map(|_| ())
            .ok_or(SecretStoreError::SecretNotFound)
    }
}

#[derive(Debug, Error)]
pub enum SecretStoreError {
    #[error("secret or key material is empty or malformed")]
    InvalidSecret,
    #[error("secret reference scope is incomplete")]
    InvalidReference,
    #[error("envelope associated-data scope is incomplete")]
    InvalidEnvelopeContext,
    #[error("encrypted content associated-data scope is incomplete")]
    InvalidContentContext,
    #[error("device handoff associated-data scope is incomplete")]
    InvalidHandoffContext,
    #[error("X25519 public key is malformed or non-contributory")]
    InvalidPublicKey,
    #[error("device handoff key derivation failed")]
    KeyDerivationFailed,
    #[error("encrypted content exceeds the bounded object size")]
    ContentTooLarge,
    #[error("secure randomness is unavailable")]
    RandomnessUnavailable,
    #[error("key envelope encryption failed")]
    EncryptionFailed,
    #[error("key envelope ciphertext is malformed")]
    InvalidCiphertext,
    #[error("key envelope scope does not match its authenticated data")]
    EnvelopeScopeMismatch,
    #[error("key envelope authentication failed")]
    AuthenticationFailed,
    #[error("operating-system secret store is unavailable")]
    BackendUnavailable,
    #[error("secret reference was not found")]
    SecretNotFound,
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hartevo_domain_kernel::{
        DeviceHandoffContext, DeviceHandoffId, DeviceId, KeyRecipient, ProjectEncryptionMode,
    };

    use super::*;

    fn context() -> EnvelopeContext {
        EnvelopeContext {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            key_version: 1,
            recipient: KeyRecipient::Device(DeviceId::from("device-1")),
            purpose: "project_content_key".into(),
            expires_at: None,
        }
    }

    fn content_context() -> ContentEncryptionContext {
        ContentEncryptionContext {
            cell: "eu".into(),
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            object_id: "mission-1".into(),
            object_kind: "mission".into(),
            object_revision: 2,
            key_version: 1,
            tombstone: false,
        }
    }

    fn handoff_context(target_public_key_digest: String) -> DeviceHandoffContext {
        DeviceHandoffContext {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            grant_id: DeviceHandoffId::from("grant-1"),
            project_mode: ProjectEncryptionMode::PersonalE2ee,
            source_recipient: KeyRecipient::Device(DeviceId::from("device-source")),
            source_envelope_digest: "a".repeat(64),
            source_keyring_manifest_digest: "b".repeat(64),
            target_device_id: DeviceId::from("device-target"),
            target_public_key_digest,
            key_version: 1,
            expected_keyring_revision: 3,
            expires_at: Utc::now() + Duration::hours(1),
        }
    }

    #[test]
    fn aes_gcm_envelope_is_bound_to_exact_project_and_recipient_scope() {
        let project_key = KeyMaterial::from_bytes([7; KEY_BYTES]).expect("project key");
        let wrapping_key = KeyMaterial::from_bytes([8; KEY_BYTES]).expect("wrapping key");
        let sealed =
            EnvelopeCrypto::seal_key(&project_key, &wrapping_key, &context()).expect("sealed key");
        let opened =
            EnvelopeCrypto::open_key(&sealed, &wrapping_key, &context()).expect("opened key");
        assert_eq!(opened.as_bytes(), project_key.as_bytes());

        let mut wrong_scope = context();
        wrong_scope.project_id = ProjectId::from("project-2");
        assert!(matches!(
            EnvelopeCrypto::open_key(&sealed, &wrapping_key, &wrong_scope),
            Err(SecretStoreError::EnvelopeScopeMismatch)
        ));
        assert!(!format!("{project_key:?}").contains("070707"));
    }

    #[test]
    fn memory_secret_store_uses_scoped_opaque_references_and_delete() {
        let store = MemorySecretStore::default();
        let reference = SecretReference {
            tenant_id: TenantId::from("tenant-1"),
            project_id: ProjectId::from("project-1"),
            provider: "local-device".into(),
            account_scope: "device-1".into(),
            purpose: "project_wrapping_key".into(),
            version: 1,
        };
        let secret = SecretBytes::new(vec![9; KEY_BYTES]).expect("secret");
        store.put(&reference, &secret).expect("put");
        assert_eq!(
            store.get(&reference).expect("get").as_slice(),
            secret.as_slice()
        );
        store.delete(&reference).expect("delete");
        assert!(matches!(
            store.get(&reference),
            Err(SecretStoreError::SecretNotFound)
        ));
        assert!(!format!("{store:?}").contains("090909"));
    }

    #[test]
    fn recipe_root_private_key_stays_in_secret_store_and_reference_is_scope_exact() {
        let store = MemorySecretStore::default();
        let reference = SecretReference::browser_recipe_root_signing_key(
            TenantId::from("tenant-recipe-root"),
            ProjectId::from("project-recipe-root"),
            "recipe-root-1",
            1,
        )
        .expect("root reference");
        // Fixed material is deliberately confined to this test fixture. A
        // production root must be generated by an approved OS/HSM boundary.
        let fixture_private_key = SecretBytes::new(vec![13; KEY_BYTES]).expect("test fixture key");
        store
            .put(&reference, &fixture_private_key)
            .expect("store root fixture");
        assert_eq!(
            store.get(&reference).expect("read root fixture").as_slice(),
            fixture_private_key.as_slice()
        );
        assert!(!format!("{reference:?}").contains("recipe-root-1"));
        assert!(!format!("{store:?}").contains("0d0d0d"));

        let another_tenant = SecretReference::browser_recipe_root_signing_key(
            TenantId::from("tenant-recipe-root-other"),
            ProjectId::from("project-recipe-root"),
            "recipe-root-1",
            1,
        )
        .expect("tenant-bound reference");
        let another_project = SecretReference::browser_recipe_root_signing_key(
            TenantId::from("tenant-recipe-root"),
            ProjectId::from("project-recipe-root-other"),
            "recipe-root-1",
            1,
        )
        .expect("project-bound reference");
        let next_generation = SecretReference::browser_recipe_root_signing_key(
            TenantId::from("tenant-recipe-root"),
            ProjectId::from("project-recipe-root"),
            "recipe-root-2",
            2,
        )
        .expect("generation-bound reference");
        let ids = [
            reference.credential_id().expect("root id"),
            another_tenant.credential_id().expect("tenant id"),
            another_project.credential_id().expect("project id"),
            next_generation.credential_id().expect("generation id"),
        ]
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 4);
        assert!(matches!(
            SecretReference::browser_recipe_root_signing_key(
                TenantId::from("tenant-recipe-root"),
                ProjectId::from("project-recipe-root"),
                "recipe-root-1",
                0,
            ),
            Err(SecretStoreError::InvalidReference)
        ));
    }

    #[test]
    fn native_secret_store_contract_reports_blocked_or_roundtrips() {
        if std::env::var("HARTEVO_RUN_NATIVE_KEYRING_SMOKE").as_deref() != Ok("1") {
            eprintln!(
                "BLOCKED_ENV: set HARTEVO_RUN_NATIVE_KEYRING_SMOKE=1 on an approved desktop host"
            );
            return;
        }
        let store = OsSecretStore::new("com.hartevo.desktop.contract-test")
            .expect("initialize native credential store");
        let unique = format!(
            "{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let reference = SecretReference {
            tenant_id: TenantId::from_stable(format!("native-smoke-tenant-{unique}")),
            project_id: ProjectId::from_stable(format!("native-smoke-project-{unique}")),
            provider: "os-native-smoke".into(),
            account_scope: format!("device:native-smoke-{unique}"),
            purpose: "ephemeral_contract_roundtrip".into(),
            version: 1,
        };
        let secret = KeyMaterial::generate().expect("ephemeral native smoke secret");
        store
            .put(&reference, &secret.to_secret())
            .expect("write native credential");
        let restored = store.get(&reference).expect("read native credential");
        assert_eq!(restored.as_slice(), secret.to_secret().as_slice());
        store
            .delete(&reference)
            .expect("delete ephemeral native credential");
        assert!(matches!(
            store.get(&reference),
            Err(SecretStoreError::SecretNotFound)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_legacy_fallback_is_exactly_missing_item_or_missing_entitlement() {
        assert!(may_use_legacy_keychain(&KeyringError::NoEntry));
        assert_eq!(
            may_use_legacy_keychain(&KeyringError::PlatformFailure(Box::new(
                security_framework::base::Error::from_code(-34_018),
            ))),
            cfg!(debug_assertions),
        );
        assert!(!may_use_legacy_keychain(&KeyringError::NoStorageAccess(
            Box::new(security_framework::base::Error::from_code(-25_291),)
        ),));
        assert!(!may_use_legacy_keychain(&KeyringError::PlatformFailure(
            Box::new(security_framework::base::Error::from_code(-25_293)),
        )));
    }

    #[test]
    fn different_seals_use_distinct_nonces() {
        let project_key = KeyMaterial::generate().expect("project key");
        let wrapping_key = KeyMaterial::generate().expect("wrapping key");
        let first = EnvelopeCrypto::seal_key(&project_key, &wrapping_key, &context())
            .expect("first envelope");
        let mut second_context = context();
        second_context.expires_at = Some(Utc::now() + Duration::minutes(5));
        let second = EnvelopeCrypto::seal_key(&project_key, &wrapping_key, &second_context)
            .expect("second envelope");
        assert_ne!(first.nonce, second.nonce);
    }

    #[test]
    fn x25519_handoff_roundtrips_only_for_exact_target_and_context() {
        let project_key = KeyMaterial::from_bytes([7; KEY_BYTES]).expect("project key");
        let target_private =
            DeviceKeyAgreementCrypto::generate_private_key().expect("target private key");
        let target_public = DeviceKeyAgreementCrypto::public_key(&target_private);
        let context = handoff_context(
            DeviceKeyAgreementCrypto::public_key_digest(&target_public).expect("target key digest"),
        );
        let sealed =
            DeviceKeyAgreementCrypto::seal_project_key(&project_key, &target_public, &context)
                .expect("sealed handoff");
        let opened = DeviceKeyAgreementCrypto::open_project_key(&sealed, &target_private, &context)
            .expect("opened handoff");
        assert_eq!(opened.as_bytes(), project_key.as_bytes());

        let wrong_private =
            DeviceKeyAgreementCrypto::generate_private_key().expect("wrong target private key");
        assert!(matches!(
            DeviceKeyAgreementCrypto::open_project_key(&sealed, &wrong_private, &context),
            Err(SecretStoreError::EnvelopeScopeMismatch)
        ));
        let mut wrong_context = context;
        wrong_context.expected_keyring_revision = 4;
        assert!(matches!(
            DeviceKeyAgreementCrypto::open_project_key(&sealed, &target_private, &wrong_context,),
            Err(SecretStoreError::EnvelopeScopeMismatch)
        ));
    }

    #[test]
    fn x25519_handoff_rejects_low_order_public_key_and_ciphertext_tampering() {
        let project_key = KeyMaterial::from_bytes([7; KEY_BYTES]).expect("project key");
        let target_private =
            DeviceKeyAgreementCrypto::generate_private_key().expect("target private key");
        let target_public = DeviceKeyAgreementCrypto::public_key(&target_private);
        let context = handoff_context(
            DeviceKeyAgreementCrypto::public_key_digest(&target_public).expect("target key digest"),
        );
        assert!(matches!(
            DeviceKeyAgreementCrypto::seal_project_key(&project_key, &[0; 32], &context),
            Err(SecretStoreError::InvalidPublicKey | SecretStoreError::EnvelopeScopeMismatch)
        ));
        let mut sealed =
            DeviceKeyAgreementCrypto::seal_project_key(&project_key, &target_public, &context)
                .expect("sealed handoff");
        sealed.ciphertext[0] ^= 1;
        assert!(matches!(
            DeviceKeyAgreementCrypto::open_project_key(&sealed, &target_private, &context),
            Err(SecretStoreError::InvalidCiphertext)
        ));
    }

    #[test]
    fn encrypted_content_is_bound_to_cell_project_object_revision_and_key_version() {
        let project_key = KeyMaterial::from_bytes([7; KEY_BYTES]).expect("project key");
        let plaintext = br#"{"mission":"private body"}"#;
        let encrypted = ContentCrypto::seal(plaintext, &project_key, &content_context())
            .expect("encrypted content");
        let opened = ContentCrypto::open(&encrypted, &project_key, &content_context())
            .expect("opened content");
        assert_eq!(opened.as_slice(), plaintext);

        let mut wrong_revision = content_context();
        wrong_revision.object_revision = 3;
        assert!(matches!(
            ContentCrypto::open(&encrypted, &project_key, &wrong_revision),
            Err(SecretStoreError::EnvelopeScopeMismatch)
        ));
        let mut tampered = encrypted;
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            ContentCrypto::open(&tampered, &project_key, &content_context()),
            Err(SecretStoreError::InvalidCiphertext)
        ));
    }
}
