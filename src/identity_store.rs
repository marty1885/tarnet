//! Identity store: named, portable keypairs that own TNS zones.
//!
//! Each Identity has one keypair, one ServiceId, one TNS zone, a privacy level,
//! and an outbound hop count. The IdentityStore replaces the flat Keystore
//! with label-based management and privacy configuration.

use std::collections::HashMap;

use crate::identity::Keypair;
use crate::types::PeerId;
use tarnet_api::types::{IdentityScheme, KemAlgo, PrivacyLevel, ServiceId, SigningAlgo};

/// A named identity with a keypair, privacy level, and outbound hop config.
pub struct Identity {
    pub label: String,
    pub keypair: Keypair,
    pub privacy: PrivacyLevel,
    pub outbound_hops: u8,
}

impl Identity {
    pub fn service_id(&self) -> ServiceId {
        self.keypair.identity.service_id()
    }
}

/// Label-indexed identity store. Each identity has a unique label and ServiceId.
pub struct IdentityStore {
    default_label: String,
    identities: HashMap<String, Identity>,
    by_service_id: HashMap<ServiceId, String>,
}

impl IdentityStore {
    /// Create a new store with a random default identity.
    pub fn new() -> Self {
        let default_kp = Keypair::generate();
        Self::with_default(default_kp, PrivacyLevel::Public, 1)
    }

    /// Create a store with a specific default keypair (for persistence).
    pub fn with_default(default_keypair: Keypair, privacy: PrivacyLevel, outbound_hops: u8) -> Self {
        let label = "default".to_string();
        let mut store = Self {
            default_label: label.clone(),
            identities: HashMap::new(),
            by_service_id: HashMap::new(),
        };
        // Use insert_identity to avoid duplication.
        store.insert_identity(&label, default_keypair, privacy, outbound_hops);
        store
    }

    /// Insert an identity (shared logic for create/import). Returns the ServiceId.
    fn insert_identity(
        &mut self,
        label: &str,
        keypair: Keypair,
        privacy: PrivacyLevel,
        outbound_hops: u8,
    ) -> ServiceId {
        let sid = keypair.identity.service_id();
        let identity = Identity {
            label: label.to_string(),
            keypair,
            privacy,
            outbound_hops,
        };
        self.by_service_id.insert(sid, label.to_string());
        self.identities.insert(label.to_string(), identity);
        sid
    }

    /// Create a new identity. Returns error if label already exists.
    pub fn create(
        &mut self,
        label: &str,
        privacy: PrivacyLevel,
        outbound_hops: u8,
        scheme: tarnet_api::types::IdentityScheme,
    ) -> Result<ServiceId, &'static str> {
        if self.identities.contains_key(label) {
            return Err("label already exists");
        }
        let kp = Keypair::generate_with_scheme(scheme);
        Ok(self.insert_identity(label, kp, privacy, outbound_hops))
    }

    pub fn get(&self, label: &str) -> Option<&Identity> {
        self.identities.get(label)
    }

    pub fn get_by_service_id(&self, sid: &ServiceId) -> Option<&Identity> {
        self.by_service_id
            .get(sid)
            .and_then(|label| self.identities.get(label))
    }

    /// Try label first, then parse as ServiceId.
    pub fn resolve_label_or_sid(&self, input: &str) -> Option<&Identity> {
        if let Some(id) = self.identities.get(input) {
            return Some(id);
        }
        // Try parsing as base32 ServiceId
        if let Ok(bytes) = tarnet_api::types::decode_base32(input) {
            if bytes.len() >= 32 {
                let mut sid_bytes = [0u8; 32];
                sid_bytes.copy_from_slice(&bytes[..32]);
                let sid = ServiceId(sid_bytes);
                return self.get_by_service_id(&sid);
            }
        }
        None
    }

    pub fn default_identity(&self) -> &Identity {
        self.identities.get(&self.default_label).unwrap()
    }

    pub fn default_service_id(&self) -> ServiceId {
        self.default_identity().service_id()
    }

    /// Backward compat: look up keypair by ServiceId.
    pub fn keypair_for(&self, sid: &ServiceId) -> Option<&Keypair> {
        self.get_by_service_id(sid).map(|id| &id.keypair)
    }

    /// Backward compat: look up PeerId (full pubkey) for a local ServiceId.
    pub fn pubkey_for(&self, sid: &ServiceId) -> Option<PeerId> {
        self.get_by_service_id(sid)
            .map(|id| id.keypair.peer_id())
    }

    /// Update an identity's privacy and outbound_hops.
    /// Returns the previous (privacy, outbound_hops) on success.
    pub fn update(
        &mut self,
        label: &str,
        privacy: PrivacyLevel,
        outbound_hops: u8,
    ) -> Result<(PrivacyLevel, u8), &'static str> {
        let identity = self.identities.get_mut(label)
            .ok_or("identity not found")?;
        let old_privacy = identity.privacy;
        let old_hops = identity.outbound_hops;
        identity.privacy = privacy;
        identity.outbound_hops = outbound_hops;
        Ok((old_privacy, old_hops))
    }

    /// Remove an identity by label. Returns the ServiceId on success.
    /// Refuses to remove the default identity.
    pub fn remove(&mut self, label: &str) -> Result<ServiceId, &'static str> {
        if label == self.default_label {
            return Err("cannot delete the default identity");
        }
        let identity = self.identities.remove(label)
            .ok_or("identity not found")?;
        let sid = identity.service_id();
        self.by_service_id.remove(&sid);
        Ok(sid)
    }

    pub fn contains_service_id(&self, sid: &ServiceId) -> bool {
        self.by_service_id.contains_key(sid)
    }

    pub fn list(&self) -> Vec<(String, ServiceId, PrivacyLevel, u8, IdentityScheme, SigningAlgo, KemAlgo)> {
        let mut identities: Vec<_> = self.identities
            .values()
            .map(|id| {
                (
                    id.label.clone(),
                    id.service_id(),
                    id.privacy,
                    id.outbound_hops,
                    id.keypair.scheme(),
                    id.keypair.identity.signing_algo(),
                    id.keypair.identity.kem_algo(),
                )
            })
            .collect();
        identities.sort_by(|a, b| a.0.cmp(&b.0));
        identities
    }

    /// Export a single identity as (label, full_key_material, privacy, outbound_hops).
    pub fn export(&self, label: &str) -> Option<(String, Vec<u8>, PrivacyLevel, u8)> {
        self.identities.get(label).map(|id| {
            (
                id.label.clone(),
                id.keypair.to_full_bytes(),
                id.privacy,
                id.outbound_hops,
            )
        })
    }

    /// Import an identity from full key material.
    pub fn import(
        &mut self,
        label: &str,
        key_material: &[u8],
        privacy: PrivacyLevel,
        outbound_hops: u8,
    ) -> Result<ServiceId, &'static str> {
        if self.identities.contains_key(label) {
            return Err("label already exists");
        }
        let kp = Keypair::from_full_bytes(key_material)?;
        Ok(self.insert_identity(label, kp, privacy, outbound_hops))
    }

    /// Import from a 32-byte Ed25519 seed (v1 migration).
    pub fn import_legacy_seed(
        &mut self,
        label: &str,
        seed: [u8; 32],
        privacy: PrivacyLevel,
        outbound_hops: u8,
    ) -> Result<ServiceId, &'static str> {
        if self.identities.contains_key(label) {
            return Err("label already exists");
        }
        #[allow(deprecated)] // Intentional: v1 migration from bare Ed25519 seed
        let kp = Keypair::from_bytes(seed);
        Ok(self.insert_identity(label, kp, privacy, outbound_hops))
    }

    /// Export all identities for persistence.
    pub fn export_all(&self) -> Vec<(String, Vec<u8>, PrivacyLevel, u8)> {
        let mut identities: Vec<_> = self.identities
            .values()
            .map(|id| {
                (
                    id.label.clone(),
                    id.keypair.to_full_bytes(),
                    id.privacy,
                    id.outbound_hops,
                )
            })
            .collect();
        identities.sort_by(|a, b| {
            let a_is_default = a.0 == self.default_label;
            let b_is_default = b.0 == self.default_label;
            b_is_default
                .cmp(&a_is_default)
                .then_with(|| a.0.cmp(&b.0))
        });
        identities
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_identity_on_init() {

        let store = IdentityStore::new();
        let default = store.default_identity();
        assert_eq!(default.label, "default");
        assert_eq!(default.privacy, PrivacyLevel::Public);
        assert_eq!(default.outbound_hops, 1);
        let sid = default.service_id();
        assert!(store.contains_service_id(&sid));
    }

    #[test]
    fn create_and_get() {

        let mut store = IdentityStore::new();
        let sid = store.create("myblog", PrivacyLevel::Hidden { intro_points: 3 }, 2, IdentityScheme::DEFAULT).unwrap();

        let identity = store.get("myblog").unwrap();
        assert_eq!(identity.label, "myblog");
        assert_eq!(identity.privacy, PrivacyLevel::Hidden { intro_points: 3 });
        assert_eq!(identity.outbound_hops, 2);
        assert_eq!(identity.service_id(), sid);
    }

    #[test]
    fn get_by_service_id() {

        let mut store = IdentityStore::new();
        let sid = store.create("test", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).unwrap();
        let identity = store.get_by_service_id(&sid).unwrap();
        assert_eq!(identity.label, "test");
    }

    #[test]
    fn duplicate_label_rejected() {

        let mut store = IdentityStore::new();
        store.create("x", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).unwrap();
        assert!(store.create("x", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).is_err());
    }

    #[test]
    fn export_import_roundtrip() {
        let mut store = IdentityStore::new();
        let sid = store.create("portable", PrivacyLevel::Hidden { intro_points: 2 }, 3, IdentityScheme::DEFAULT).unwrap();

        let (label, key_material, privacy, hops) = store.export("portable").unwrap();
        assert_eq!(label, "portable");
        assert_eq!(privacy, PrivacyLevel::Hidden { intro_points: 2 });
        assert_eq!(hops, 3);

        let mut store2 = IdentityStore::new();
        let sid2 = store2.import("portable", &key_material, privacy, hops).unwrap();
        assert_eq!(sid, sid2);
    }

    #[test]
    fn update_privacy() {

        let mut store = IdentityStore::new();
        store.create("svc", PrivacyLevel::Hidden { intro_points: 3 }, 2, IdentityScheme::DEFAULT).unwrap();

        // Update to public
        let (old_priv, old_hops) = store.update("svc", PrivacyLevel::Public, 1).unwrap();
        assert_eq!(old_priv, PrivacyLevel::Hidden { intro_points: 3 });
        assert_eq!(old_hops, 2);

        // Verify the update took effect
        let id = store.get("svc").unwrap();
        assert_eq!(id.privacy, PrivacyLevel::Public);
        assert_eq!(id.outbound_hops, 1);
    }

    #[test]
    fn remove_identity() {
        let mut store = IdentityStore::new();
        let sid = store.create("temp", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).unwrap();
        assert!(store.get("temp").is_some());
        assert!(store.contains_service_id(&sid));

        let removed_sid = store.remove("temp").unwrap();
        assert_eq!(removed_sid, sid);
        assert!(store.get("temp").is_none());
        assert!(!store.contains_service_id(&sid));
    }

    #[test]
    fn remove_default_rejected() {
        let mut store = IdentityStore::new();
        assert!(store.remove("default").is_err());
    }

    #[test]
    fn remove_nonexistent_fails() {
        let mut store = IdentityStore::new();
        assert!(store.remove("nope").is_err());
    }

    #[test]
    fn update_nonexistent_fails() {

        let mut store = IdentityStore::new();
        assert!(store.update("nope", PrivacyLevel::Public, 1).is_err());
    }

    #[test]
    fn list_identities() {

        let mut store = IdentityStore::new();
        store.create("a", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).unwrap();
        store.create("b", PrivacyLevel::Hidden { intro_points: 1 }, 2, IdentityScheme::DEFAULT).unwrap();
        let list = store.list();
        assert_eq!(list.len(), 3); // default + a + b
        assert_eq!(list[0].0, "a");
        assert_eq!(list[1].0, "b");
        assert_eq!(list[2].0, "default");
    }

    #[test]
    fn export_all_keeps_default_first() {
        let mut store = IdentityStore::new();
        store.create("z", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).unwrap();
        store.create("a", PrivacyLevel::Hidden { intro_points: 2 }, 2, IdentityScheme::DEFAULT).unwrap();

        let exported = store.export_all();
        assert_eq!(exported[0].0, "default");
        assert_eq!(exported[1].0, "a");
        assert_eq!(exported[2].0, "z");
    }

    #[test]
    fn keypair_for_backward_compat() {

        let store = IdentityStore::new();
        let sid = store.default_service_id();
        assert!(store.keypair_for(&sid).is_some());
        assert!(store.pubkey_for(&sid).is_some());
    }

    #[test]
    fn resolve_label_or_sid() {

        let mut store = IdentityStore::new();
        store.create("myservice", PrivacyLevel::Public, 1, IdentityScheme::DEFAULT).unwrap();

        // Resolve by label
        assert!(store.resolve_label_or_sid("myservice").is_some());

        // Resolve by base32 ServiceId
        let sid = store.get("myservice").unwrap().service_id();
        let base32 = format!("{}", sid);
        assert!(store.resolve_label_or_sid(&base32).is_some());
    }
}
