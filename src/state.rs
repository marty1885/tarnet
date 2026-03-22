use std::path::Path;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use rusqlite::{params, Connection, OptionalExtension};

use crate::dht::DhtRecord;
use crate::types::{DhtId, Error, PrivacyLevel, RecordType, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StorageLimits {
    pub max_records: usize,
    pub max_total_bytes: usize,
    pub max_records_per_key: usize,
    pub max_bytes_per_key: usize,
    pub max_value_bytes: usize,
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_records: 4_096,
            max_total_bytes: 16 * 1024 * 1024,
            max_records_per_key: 16,
            max_bytes_per_key: 256 * 1024,
            max_value_bytes: 64 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedRecord {
    pub key: [u8; 64],
    pub record_type: u8,
    pub sequence: u64,
    pub signer: [u8; 32],
    pub ttl_secs: u64,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
}

impl PersistedRecord {
    pub fn from_live(record: &DhtRecord) -> Option<Self> {
        if record.is_expired() {
            return None;
        }
        let remaining_ttl = record.ttl.checked_sub(record.stored_at.elapsed())?;
        Some(Self {
            key: *record.key.as_bytes(),
            record_type: record.record_type.as_u8(),
            sequence: record.sequence,
            signer: record.signer,
            ttl_secs: remaining_ttl.as_secs().max(1),
            value: record.value.clone(),
            signature: record.signature.to_vec(),
            signer_algo: record.signer_algo,
            signer_pubkey: record.signer_pubkey.clone(),
        })
    }

    pub fn into_live(self) -> DhtRecord {
        DhtRecord {
            key: DhtId(self.key),
            record_type: RecordType::from_u8(self.record_type),
            sequence: self.sequence,
            signer: self.signer,
            signer_algo: self.signer_algo,
            signer_pubkey: self.signer_pubkey,
            value: self.value,
            ttl: Duration::from_secs(self.ttl_secs),
            stored_at: Instant::now(),
            signature: self.signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedIdentity {
    pub label: String,
    pub scheme: u8,
    pub signing_key_material: Vec<u8>,
    pub kem_key_material: Vec<u8>,
    pub signing_algo: u8,
    pub kem_algo: u8,
    pub privacy: PrivacyLevel,
    pub outbound_hops: u8,
    pub is_default: bool,
}

/// Pure write-through persistent storage.
///
/// Every mutation is a single atomic SQL statement — no transactions,
/// no dirty tracking, no periodic flush.
pub struct StateDb {
    conn: StdMutex<Connection>,
}

// Safety: rusqlite::Connection is Send but not Sync.
// We protect it with std::sync::Mutex, so StateDb is Send + Sync.
unsafe impl Sync for StateDb {}

impl StateDb {
    /// Open (or create) the database at `path`.
    /// Creates tables, enables WAL mode, sets busy timeout.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(Error::Io)?;
            }
        }

        let conn = Connection::open(path).map_err(sqlite_err)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(sqlite_err)?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(sqlite_err)?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(sqlite_err)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                 key TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS identities (
                 label TEXT PRIMARY KEY,
                 identity_scheme INTEGER NOT NULL DEFAULT 1,
                 signing_key_material BLOB NOT NULL,
                 kem_key_material BLOB NOT NULL DEFAULT X'',
                 signing_algo INTEGER NOT NULL DEFAULT 1,
                 kem_algo INTEGER NOT NULL DEFAULT 1,
                 privacy_type INTEGER NOT NULL DEFAULT 0,
                 privacy_param INTEGER NOT NULL DEFAULT 0,
                 outbound_hops INTEGER NOT NULL DEFAULT 1,
                 is_default INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS dht_records (
                 key BLOB NOT NULL,
                 signer BLOB NOT NULL,
                 record_type INTEGER NOT NULL,
                 sequence INTEGER NOT NULL,
                 ttl_secs INTEGER NOT NULL,
                 value BLOB NOT NULL,
                 signature BLOB NOT NULL,
                 signer_algo INTEGER NOT NULL DEFAULT 1,
                 signer_pubkey BLOB NOT NULL DEFAULT X'',
                 PRIMARY KEY (key, signer)
             );
             CREATE TABLE IF NOT EXISTS tns_labels (
                 label TEXT PRIMARY KEY,
                 publish INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS tns_records (
                 label TEXT NOT NULL,
                 record BLOB NOT NULL,
                 FOREIGN KEY (label) REFERENCES tns_labels(label) ON DELETE CASCADE
             );",
        )
        .map_err(sqlite_err)?;

        // Enable foreign key support (required for ON DELETE CASCADE).
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(sqlite_err)?;

        // Migrate legacy petnames table if it exists.
        let has_petnames: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='petnames'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(sqlite_err)?
            > 0;
        if has_petnames {
            // Migrate each petname to a Zone record (tag 0x01 + 32 bytes ServiceId).
            // We must do this row-by-row because SQLite's || operator on hex
            // literals and BLOBs can produce TEXT in some configurations.
            {
                let mut stmt = conn
                    .prepare("SELECT name, zone_pubkey FROM petnames")
                    .map_err(sqlite_err)?;
                let rows: Vec<(String, Vec<u8>)> = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                    })
                    .map_err(sqlite_err)?
                    .filter_map(|r| r.ok())
                    .collect();
                for (name, zone_pubkey) in rows {
                    conn.execute(
                        "INSERT OR IGNORE INTO tns_labels(label, publish) VALUES(?1, 0)",
                        params![name],
                    )
                    .map_err(sqlite_err)?;
                    let mut record_blob = Vec::with_capacity(1 + zone_pubkey.len());
                    record_blob.push(0x01); // TAG_ZONE
                    record_blob.extend_from_slice(&zone_pubkey);
                    conn.execute(
                        "INSERT OR IGNORE INTO tns_records(label, record) VALUES(?1, ?2)",
                        params![name, record_blob],
                    )
                    .map_err(sqlite_err)?;
                }
            }
            conn.execute_batch("DROP TABLE petnames;")
                .map_err(sqlite_err)?;
        }

        Ok(Self {
            conn: StdMutex::new(conn),
        })
    }

    // ── Metadata ──

    pub fn get_metadata(&self, key: &str) -> Result<Option<u64>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT value FROM metadata WHERE key = ?1",
            params![key],
            |row| row.get::<_, u64>(0),
        )
        .optional()
        .map_err(sqlite_err)
    }

    pub fn set_metadata(&self, key: &str, value: u64) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO metadata(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    // ── Identities ──

    pub fn load_identities(&self) -> Result<Vec<PersistedIdentity>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT label, identity_scheme, signing_key_material, kem_key_material,
                        signing_algo, kem_algo, privacy_type, privacy_param,
                        outbound_hops, is_default
                 FROM identities ORDER BY label ASC",
            )
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| {
                let privacy_type: u8 = row.get(6)?;
                let privacy_param: u8 = row.get(7)?;
                let privacy = match privacy_type {
                    1 => PrivacyLevel::Hidden {
                        intro_points: privacy_param,
                    },
                    _ => PrivacyLevel::Public,
                };
                Ok(PersistedIdentity {
                    label: row.get(0)?,
                    scheme: row.get(1)?,
                    signing_key_material: row.get(2)?,
                    kem_key_material: row.get(3)?,
                    signing_algo: row.get(4)?,
                    kem_algo: row.get(5)?,
                    privacy,
                    outbound_hops: row.get(8)?,
                    is_default: row.get(9)?,
                })
            })
            .map_err(sqlite_err)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(sqlite_err)?);
        }
        Ok(result)
    }

    pub fn save_identity(&self, id: &PersistedIdentity) -> Result<()> {
        let (privacy_type, privacy_param): (u8, u8) = match id.privacy {
            PrivacyLevel::Public => (0, 0),
            PrivacyLevel::Hidden { intro_points } => (1, intro_points),
        };
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO identities(label, identity_scheme, signing_key_material, kem_key_material,
                                    signing_algo, kem_algo, privacy_type, privacy_param,
                                    outbound_hops, is_default)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(label) DO UPDATE SET
                 identity_scheme = excluded.identity_scheme,
                 signing_key_material = excluded.signing_key_material,
                 kem_key_material = excluded.kem_key_material,
                 signing_algo = excluded.signing_algo,
                 kem_algo = excluded.kem_algo,
                 privacy_type = excluded.privacy_type,
                 privacy_param = excluded.privacy_param,
                 outbound_hops = excluded.outbound_hops,
                 is_default = excluded.is_default",
            params![
                id.label,
                id.scheme,
                &id.signing_key_material,
                &id.kem_key_material,
                id.signing_algo,
                id.kem_algo,
                privacy_type,
                privacy_param,
                id.outbound_hops,
                id.is_default,
            ],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    pub fn delete_identity(&self, label: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute("DELETE FROM identities WHERE label = ?1", params![label])
            .map_err(sqlite_err)?;
        Ok(())
    }

    // ── DHT Records ──

    pub fn load_dht_records(&self) -> Result<Vec<PersistedRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT key, signer, record_type, sequence, ttl_secs, value,
                        signature, signer_algo, signer_pubkey
                 FROM dht_records",
            )
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok(PersistedRecord {
                    key: vec_to_array::<64>(row.get::<_, Vec<u8>>(0)?)?,
                    signer: vec_to_array::<32>(row.get::<_, Vec<u8>>(1)?)?,
                    record_type: row.get(2)?,
                    sequence: row.get(3)?,
                    ttl_secs: row.get(4)?,
                    value: row.get(5)?,
                    signature: row.get(6)?,
                    signer_algo: row.get(7)?,
                    signer_pubkey: row.get(8)?,
                })
            })
            .map_err(sqlite_err)?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row.map_err(sqlite_err)?);
        }
        Ok(result)
    }

    pub fn upsert_dht_record(&self, record: &PersistedRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO dht_records(key, signer, record_type, sequence, ttl_secs, value,
                                     signature, signer_algo, signer_pubkey)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(key, signer) DO UPDATE SET
                 record_type = excluded.record_type,
                 sequence = excluded.sequence,
                 ttl_secs = excluded.ttl_secs,
                 value = excluded.value,
                 signature = excluded.signature,
                 signer_algo = excluded.signer_algo,
                 signer_pubkey = excluded.signer_pubkey",
            params![
                &record.key[..],
                &record.signer[..],
                record.record_type,
                record.sequence,
                record.ttl_secs,
                &record.value,
                &record.signature,
                record.signer_algo,
                &record.signer_pubkey,
            ],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    pub fn delete_dht_record(&self, key: &[u8; 64], signer: &[u8; 32]) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM dht_records WHERE key = ?1 AND signer = ?2",
            params![&key[..], &signer[..]],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    // ── Labels (TNS local store) ──

    pub fn label_set(&self, label: &str, records: &[Vec<u8>], publish: bool) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO tns_labels(label, publish) VALUES(?1, ?2)
             ON CONFLICT(label) DO UPDATE SET publish = excluded.publish",
            params![label, publish as i32],
        )
        .map_err(sqlite_err)?;
        conn.execute(
            "DELETE FROM tns_records WHERE label = ?1",
            params![label],
        )
        .map_err(sqlite_err)?;
        for rec_bytes in records {
            conn.execute(
                "INSERT INTO tns_records(label, record) VALUES(?1, ?2)",
                params![label, rec_bytes],
            )
            .map_err(sqlite_err)?;
        }
        Ok(())
    }

    pub fn label_get(&self, label: &str) -> Result<Option<(Vec<Vec<u8>>, bool)>> {
        let conn = self.lock()?;
        let publish: Option<bool> = conn
            .query_row(
                "SELECT publish FROM tns_labels WHERE label = ?1",
                params![label],
                |row| {
                    let v: i32 = row.get(0)?;
                    Ok(v != 0)
                },
            )
            .optional()
            .map_err(sqlite_err)?;
        let publish = match publish {
            Some(p) => p,
            None => return Ok(None),
        };
        let mut stmt = conn
            .prepare("SELECT record FROM tns_records WHERE label = ?1")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![label], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sqlite_err)?;
        let mut records = Vec::new();
        for row in rows {
            records.push(row.map_err(sqlite_err)?);
        }
        Ok(Some((records, publish)))
    }

    pub fn label_remove(&self, label: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM tns_labels WHERE label = ?1",
            params![label],
        )
        .map_err(sqlite_err)?;
        Ok(())
    }

    pub fn label_list(&self) -> Result<Vec<(String, Vec<Vec<u8>>, bool)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare("SELECT label, publish FROM tns_labels ORDER BY label")
            .map_err(sqlite_err)?;
        let label_rows = stmt
            .query_map([], |row| {
                let label: String = row.get(0)?;
                let publish: i32 = row.get(1)?;
                Ok((label, publish != 0))
            })
            .map_err(sqlite_err)?;
        let mut labels: Vec<(String, bool)> = Vec::new();
        for row in label_rows {
            labels.push(row.map_err(sqlite_err)?);
        }
        let mut result = Vec::new();
        for (label, publish) in labels {
            let mut rec_stmt = conn
                .prepare("SELECT record FROM tns_records WHERE label = ?1")
                .map_err(sqlite_err)?;
            let rec_rows = rec_stmt
                .query_map(params![&label], |row| row.get::<_, Vec<u8>>(0))
                .map_err(sqlite_err)?;
            let mut records = Vec::new();
            for rec in rec_rows {
                records.push(rec.map_err(sqlite_err)?);
            }
            result.push((label, records, publish));
        }
        Ok(result)
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|e| Error::Protocol(format!("state db lock: {}", e)))
    }

    /// Expose the inner connection for test assertions.
    #[cfg(test)]
    pub fn lock_for_test(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap()
    }
}

fn sqlite_err(err: rusqlite::Error) -> Error {
    Error::Protocol(format!("sqlite error: {}", err))
}

fn vec_to_array<const N: usize>(value: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    if value.len() != N {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            value.len(),
            rusqlite::types::Type::Blob,
            format!("expected {} bytes, got {}", N, value.len()).into(),
        ));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&value);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn state_db_roundtrip() {
        let path = temp_db_path("db-roundtrip");
        let db = StateDb::open(&path).unwrap();

        // Metadata
        db.set_metadata("hello_sequence", 7).unwrap();
        db.set_metadata("signed_content_sequence", 11).unwrap();
        assert_eq!(db.get_metadata("hello_sequence").unwrap(), Some(7));
        assert_eq!(db.get_metadata("signed_content_sequence").unwrap(), Some(11));

        // Identity
        let id = PersistedIdentity {
            label: "default".to_string(),
            scheme: 1,
            signing_key_material: vec![0xAB; 32],
            kem_key_material: vec![],
            signing_algo: 1,
            kem_algo: 1,
            privacy: PrivacyLevel::Public,
            outbound_hops: 1,
            is_default: true,
        };
        db.save_identity(&id).unwrap();
        let loaded_ids = db.load_identities().unwrap();
        assert_eq!(loaded_ids.len(), 1);
        assert_eq!(loaded_ids[0], id);

        // DHT record
        let record = PersistedRecord {
            key: [1u8; 64],
            record_type: RecordType::SignedContent.as_u8(),
            sequence: 3,
            signer: [2u8; 32],
            ttl_secs: 42,
            value: b"value".to_vec(),
            signature: vec![3u8; 64],
            signer_algo: 1,
            signer_pubkey: vec![4u8; 32],
        };
        db.upsert_dht_record(&record).unwrap();
        let loaded_records = db.load_dht_records().unwrap();
        assert_eq!(loaded_records.len(), 1);
        assert_eq!(loaded_records[0], record);

        // Labels
        let zone_rec = vec![1u8, 0x42, 0x42, 0x42]; // dummy record blob
        db.label_set("alice", &[zone_rec.clone()], false).unwrap();
        let result = db.label_get("alice").unwrap();
        assert!(result.is_some());
        let (blobs, publish) = result.unwrap();
        assert_eq!(blobs, vec![zone_rec]);
        assert!(!publish);
        let list = db.label_list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "alice");
        db.label_remove("alice").unwrap();
        assert!(db.label_get("alice").unwrap().is_none());

        cleanup(&path);
    }

    #[test]
    fn dht_record_upsert() {
        let path = temp_db_path("dht-upsert");
        let db = StateDb::open(&path).unwrap();

        let record = PersistedRecord {
            key: [1u8; 64],
            record_type: 1,
            sequence: 1,
            signer: [2u8; 32],
            ttl_secs: 100,
            value: b"v1".to_vec(),
            signature: vec![0; 64],
            signer_algo: 1,
            signer_pubkey: vec![0; 32],
        };
        db.upsert_dht_record(&record).unwrap();

        // Upsert same key+signer with new sequence
        let updated = PersistedRecord {
            sequence: 2,
            value: b"v2".to_vec(),
            ..record.clone()
        };
        db.upsert_dht_record(&updated).unwrap();
        let loaded = db.load_dht_records().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sequence, 2);
        assert_eq!(loaded[0].value, b"v2");

        // Delete
        db.delete_dht_record(&record.key, &record.signer).unwrap();
        assert!(db.load_dht_records().unwrap().is_empty());

        cleanup(&path);
    }

    #[test]
    fn identity_upsert() {
        let path = temp_db_path("id-upsert");
        let db = StateDb::open(&path).unwrap();

        let id = PersistedIdentity {
            label: "test".to_string(),
            scheme: 1,
            signing_key_material: vec![0x01; 32],
            kem_key_material: vec![],
            signing_algo: 1,
            kem_algo: 1,
            privacy: PrivacyLevel::Public,
            outbound_hops: 1,
            is_default: false,
        };
        db.save_identity(&id).unwrap();

        // Update privacy
        let updated = PersistedIdentity {
            privacy: PrivacyLevel::Hidden { intro_points: 3 },
            ..id.clone()
        };
        db.save_identity(&updated).unwrap();
        let loaded = db.load_identities().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].privacy, PrivacyLevel::Hidden { intro_points: 3 });

        // Delete
        db.delete_identity("test").unwrap();
        assert!(db.load_identities().unwrap().is_empty());

        cleanup(&path);
    }

    #[test]
    fn persisted_record_signature_verifies() {
        use crate::identity::{self, Keypair, peer_id_from_signing_pubkey};
        use crate::wire::DhtPutMsg;
        use tarnet_api::types::SigningAlgo;

        let kp = Keypair::generate_classic();
        let peer_id = kp.peer_id();
        let signer = *peer_id.as_bytes();
        let key = [0xABu8; 64];
        let value = b"hello-record-value".to_vec();

        let mut put = DhtPutMsg {
            key,
            record_type: RecordType::Hello,
            sequence: 1,
            signer,
            ttl: 600,
            value: value.clone(),
            signature: Vec::new(),
            signer_algo: kp.identity.signing_algo() as u8,
            signer_pubkey: kp.identity.signing.signing_pubkey_bytes(),
            hop_count: 0,
            hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
            bloom: [0u8; 256],
        };
        put.signature = kp.sign(&put.signable_bytes());

        let algo = SigningAlgo::from_u8(put.signer_algo).unwrap();
        assert!(identity::verify(algo, &put.signer_pubkey, &put.signable_bytes(), &put.signature));

        let record = DhtRecord {
            key: crate::types::DhtId(key),
            record_type: RecordType::Hello,
            sequence: 1,
            signer,
            signer_algo: put.signer_algo,
            signer_pubkey: put.signer_pubkey.clone(),
            value: value.clone(),
            ttl: Duration::from_secs(600),
            stored_at: Instant::now(),
            signature: put.signature.clone(),
        };
        let persisted = PersistedRecord::from_live(&record).unwrap();
        let path = temp_db_path("sig-verify");
        let db = StateDb::open(&path).unwrap();
        db.upsert_dht_record(&persisted).unwrap();

        let loaded_records = db.load_dht_records().unwrap();
        let loaded = loaded_records[0].clone().into_live();

        let forwarded_put = DhtPutMsg {
            key: *loaded.key.as_bytes(),
            record_type: loaded.record_type,
            sequence: loaded.sequence,
            signer: loaded.signer,
            ttl: loaded.ttl.as_secs() as u32,
            value: loaded.value.clone(),
            signature: loaded.signature.clone(),
            signer_algo: loaded.signer_algo,
            signer_pubkey: loaded.signer_pubkey.clone(),
            hop_count: 0,
            hop_limit: DhtPutMsg::DEFAULT_HOP_LIMIT,
            bloom: [0u8; 256],
        };

        let algo = SigningAlgo::from_u8(forwarded_put.signer_algo).unwrap();
        assert!(
            !forwarded_put.signer_pubkey.is_empty(),
            "signer_pubkey must survive persistence"
        );
        let expected_peer = peer_id_from_signing_pubkey(&forwarded_put.signer_pubkey);
        assert_eq!(
            expected_peer,
            crate::types::PeerId(forwarded_put.signer),
            "signer_pubkey must match signer PeerId"
        );
        assert!(
            identity::verify(
                algo,
                &forwarded_put.signer_pubkey,
                &forwarded_put.signable_bytes(),
                &forwarded_put.signature,
            ),
            "signature must verify after persist→load→forward round-trip"
        );

        cleanup(&path);
    }

    fn temp_db_path(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("tarnet-{}-{}.sqlite3", tag, nanos))
    }

    fn cleanup(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{}-wal", path.display()));
        let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    }
}
