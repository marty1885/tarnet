use std::path::Path;
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, OptionalExtension};

use crate::dht::{DhtRecord, RecordSource};
use crate::types::{DhtId, Error, PeerId, PrivacyLevel, RecordType, Result};

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
            // Must leave room for the DhtPut wire envelope (~2 KB worst case:
            // 64-byte key + 256-byte bloom + Falcon+Ed25519 signature & pubkey +
            // fixed fields) so a stored record always fits MAX_PAYLOAD (65535)
            // and can be forwarded. A record that can't be forwarded is useless
            // and would silently fail to propagate, so reject it at store time.
            max_value_bytes: 60 * 1024,
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
    pub expires_at_unix: u64,
    /// Who handed us the record: `None` if this node minted it, else the
    /// link peer that delivered it. Persisted so a restarted node still knows
    /// which records are its own to republish.
    pub source: Option<[u8; 32]>,
    pub value: Vec<u8>,
    pub signature: Vec<u8>,
    pub signer_algo: u8,
    pub signer_pubkey: Vec<u8>,
}

impl PersistedRecord {
    /// The row for a stored record and who handed it to us. Lifetimes are
    /// kept on this node's own wall clock across restarts (nodes never
    /// compare clocks): `expires_at_unix` is now plus the remaining TTL, and
    /// `ttl_secs` that remaining TTL.
    pub fn from_stored(record: &DhtRecord, source: RecordSource) -> Option<Self> {
        if record.is_expired() {
            return None;
        }
        let ttl_secs = record.remaining_ttl().as_secs().max(1);
        Some(Self {
            key: *record.key.as_bytes(),
            record_type: record.record_type.as_u8(),
            sequence: record.sequence,
            signer: *record.signer.as_bytes(),
            ttl_secs,
            expires_at_unix: unix_now_secs().saturating_add(ttl_secs),
            source: match source {
                RecordSource::Local => None,
                RecordSource::Peer(p) => Some(*p.as_bytes()),
            },
            value: record.value.clone(),
            signature: record.signature.to_vec(),
            signer_algo: record.signer_algo,
            signer_pubkey: record.signer_pubkey.clone(),
        })
    }

    /// Back to a live record with what is left of its TTL, or `None` if it
    /// has expired. Fails safe on a clock that can't be trusted: if the clock
    /// is now earlier than when the row was written (no RTC, reset), the
    /// downtime is unknown and the record is dropped; it never gets more than
    /// the TTL it had when written.
    pub fn into_stored(self) -> Option<(DhtRecord, RecordSource)> {
        let now = unix_now_secs();
        let written = self.expires_at_unix.saturating_sub(self.ttl_secs);
        if now < written || self.expires_at_unix <= now {
            return None;
        }
        let remaining = (self.expires_at_unix - now).min(self.ttl_secs);
        let source = match self.source {
            None => RecordSource::Local,
            Some(p) => RecordSource::Peer(PeerId(p)),
        };
        let record = DhtRecord {
            key: DhtId(self.key),
            record_type: RecordType::from_u8(self.record_type),
            sequence: self.sequence,
            signer: PeerId(self.signer),
            signer_algo: self.signer_algo,
            signer_pubkey: self.signer_pubkey,
            value: self.value,
            expires: Instant::now() + Duration::from_secs(remaining),
            stored_at: Instant::now(),
            signature: self.signature,
        };
        Some((record, source))
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
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(sqlite_err)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (
                 key TEXT PRIMARY KEY,
                 value INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS identities (
                 label TEXT PRIMARY KEY,
                 identity_scheme INTEGER NOT NULL,
                 signing_key_material BLOB NOT NULL,
                 kem_key_material BLOB NOT NULL,
                 signing_algo INTEGER NOT NULL,
                 kem_algo INTEGER NOT NULL,
                 privacy_type INTEGER NOT NULL,
                 privacy_param INTEGER NOT NULL,
                 outbound_hops INTEGER NOT NULL,
                 is_default INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tns_labels (
                 identity TEXT NOT NULL DEFAULT '',
                 label TEXT NOT NULL,
                 publish INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (identity, label)
             );
             CREATE TABLE IF NOT EXISTS tns_records (
                 identity TEXT NOT NULL DEFAULT '',
                 label TEXT NOT NULL,
                 record BLOB NOT NULL,
                 FOREIGN KEY (identity, label) REFERENCES tns_labels(identity, label) ON DELETE CASCADE
             );
             CREATE TABLE IF NOT EXISTS pools (
                 name TEXT PRIMARY KEY,
                 kind INTEGER NOT NULL,
                 key BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS tns_zone_records (
                 zone_sid BLOB NOT NULL,
                 label TEXT NOT NULL,
                 records BLOB NOT NULL,
                 PRIMARY KEY (zone_sid, label)
             );",
        )
        .map_err(sqlite_err)?;
        ensure_dht_records_table(&conn).map_err(sqlite_err)?;

        Ok(Self {
            conn: StdMutex::new(conn),
        })
    }

    // ── Metadata ──

    pub fn get_metadata(&self, key: &str) -> Result<Option<u64>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("SELECT value FROM metadata WHERE key = ?1")
            .map_err(sqlite_err)?;
        stmt.query_row(params![key], |row| row.get::<_, u64>(0))
            .optional()
            .map_err(sqlite_err)
    }

    pub fn set_metadata(&self, key: &str, value: u64) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO metadata(key, value) VALUES(?1, ?2)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            )
            .map_err(sqlite_err)?;
        stmt.execute(params![key, value]).map_err(sqlite_err)?;
        Ok(())
    }

    // ── Identities ──

    pub fn load_identities(&self) -> Result<Vec<PersistedIdentity>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
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
        let result = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_err);
        result
    }

    pub fn save_identity(&self, id: &PersistedIdentity) -> Result<()> {
        let (privacy_type, privacy_param): (u8, u8) = match id.privacy {
            PrivacyLevel::Public => (0, 0),
            PrivacyLevel::Hidden { intro_points } => (1, intro_points),
        };
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
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
            )
            .map_err(sqlite_err)?;
        stmt.execute(params![
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
        ])
        .map_err(sqlite_err)?;
        Ok(())
    }

    pub fn delete_identity(&self, label: &str) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("DELETE FROM identities WHERE label = ?1")
            .map_err(sqlite_err)?;
        stmt.execute(params![label]).map_err(sqlite_err)?;
        Ok(())
    }

    // ── Pools (virtual cluster membership) ──

    /// Load all joined pools as (name, kind_tag, key_blob). kind_tag 0 = Closed.
    pub fn load_pools(&self) -> Result<Vec<(String, u8, Vec<u8>)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("SELECT name, kind, key FROM pools")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)? as u8,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })
            .map_err(sqlite_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(sqlite_err)?);
        }
        Ok(out)
    }

    pub fn save_pool(&self, name: &str, kind: u8, key: &[u8]) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "INSERT INTO pools(name, kind, key) VALUES(?1, ?2, ?3)
                 ON CONFLICT(name) DO UPDATE SET kind = excluded.kind, key = excluded.key",
            )
            .map_err(sqlite_err)?;
        stmt.execute(params![name, kind as i64, key])
            .map_err(sqlite_err)?;
        Ok(())
    }

    pub fn delete_pool(&self, name: &str) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("DELETE FROM pools WHERE name = ?1")
            .map_err(sqlite_err)?;
        stmt.execute(params![name]).map_err(sqlite_err)?;
        Ok(())
    }

    // ── DHT Records ──

    pub fn load_dht_records(&self) -> Result<Vec<PersistedRecord>> {
        let conn = self.lock()?;
        let now = unix_now_secs();
        let mut stmt = conn
            .prepare_cached(
                "SELECT key, signer, record_type, sequence, ttl_secs, expires_at_unix, source,
                        value, signature, signer_algo, signer_pubkey
                 FROM dht_records
                 WHERE expires_at_unix > ?1",
            )
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![now], |row| {
                Ok(PersistedRecord {
                    key: vec_to_array::<64>(row.get::<_, Vec<u8>>(0)?)?,
                    signer: vec_to_array::<32>(row.get::<_, Vec<u8>>(1)?)?,
                    record_type: row.get(2)?,
                    sequence: row.get(3)?,
                    ttl_secs: row.get(4)?,
                    expires_at_unix: row.get(5)?,
                    source: row
                        .get::<_, Option<Vec<u8>>>(6)?
                        .map(vec_to_array::<32>)
                        .transpose()?,
                    value: row.get(7)?,
                    signature: row.get(8)?,
                    signer_algo: row.get(9)?,
                    signer_pubkey: row.get(10)?,
                })
            })
            .map_err(sqlite_err)?;
        let result = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_err);
        result
    }

    /// Write a record's row, replacing whatever its signer had at its key.
    pub fn upsert_dht_record(&self, record: &PersistedRecord) -> Result<()> {
        let conn = self.lock()?;
        conn.prepare_cached(
            "INSERT OR REPLACE INTO dht_records(key, signer, record_type, sequence, ttl_secs,
                                                expires_at_unix, source, value, signature,
                                                signer_algo, signer_pubkey)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        )
        .map_err(sqlite_err)?
        .execute(params![
            &record.key[..],
            &record.signer[..],
            record.record_type,
            record.sequence,
            record.ttl_secs,
            record.expires_at_unix,
            record.source.as_ref().map(|p| &p[..]),
            &record.value,
            &record.signature,
            record.signer_algo,
            &record.signer_pubkey,
        ])
        .map_err(sqlite_err)?;
        Ok(())
    }

    /// Delete the row of a record the store no longer holds.
    pub fn delete_dht_record(&self, key: &[u8; 64], signer: &[u8; 32]) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("DELETE FROM dht_records WHERE key = ?1 AND signer = ?2")
            .map_err(sqlite_err)?;
        stmt.execute(params![&key[..], &signer[..]])
            .map_err(sqlite_err)?;
        Ok(())
    }

    pub fn delete_expired_dht_records(&self) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("DELETE FROM dht_records WHERE expires_at_unix <= ?1")
            .map_err(sqlite_err)?;
        stmt.execute(params![unix_now_secs()]).map_err(sqlite_err)?;
        Ok(())
    }

    // ── Labels (TNS local store) ──

    pub fn label_set(
        &self,
        identity: &str,
        label: &str,
        records: &[Vec<u8>],
        publish: bool,
    ) -> Result<()> {
        let conn = self.lock()?;
        conn.execute_batch("BEGIN").map_err(sqlite_err)?;
        let result = (|| {
            conn.prepare_cached(
                "INSERT INTO tns_labels(identity, label, publish) VALUES(?1, ?2, ?3)
                 ON CONFLICT(identity, label) DO UPDATE SET publish = excluded.publish",
            )
            .map_err(sqlite_err)?
            .execute(params![identity, label, publish as i32])
            .map_err(sqlite_err)?;
            conn.prepare_cached("DELETE FROM tns_records WHERE identity = ?1 AND label = ?2")
                .map_err(sqlite_err)?
                .execute(params![identity, label])
                .map_err(sqlite_err)?;
            let mut ins = conn
                .prepare_cached(
                    "INSERT INTO tns_records(identity, label, record) VALUES(?1, ?2, ?3)",
                )
                .map_err(sqlite_err)?;
            for rec_bytes in records {
                ins.execute(params![identity, label, rec_bytes])
                    .map_err(sqlite_err)?;
            }
            Ok(())
        })();
        if result.is_ok() {
            conn.execute_batch("COMMIT").map_err(sqlite_err)?;
        } else {
            let _ = conn.execute_batch("ROLLBACK");
        }
        result
    }

    pub fn label_get(&self, identity: &str, label: &str) -> Result<Option<(Vec<Vec<u8>>, bool)>> {
        let conn = self.lock()?;
        let publish: Option<bool> = {
            let mut stmt = conn
                .prepare_cached("SELECT publish FROM tns_labels WHERE identity = ?1 AND label = ?2")
                .map_err(sqlite_err)?;
            stmt.query_row(params![identity, label], |row| {
                let v: i32 = row.get(0)?;
                Ok(v != 0)
            })
            .optional()
            .map_err(sqlite_err)?
        };
        let publish = match publish {
            Some(p) => p,
            None => return Ok(None),
        };
        let mut stmt = conn
            .prepare_cached("SELECT record FROM tns_records WHERE identity = ?1 AND label = ?2")
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![identity, label], |row| row.get::<_, Vec<u8>>(0))
            .map_err(sqlite_err)?;
        let records = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_err)?;
        Ok(Some((records, publish)))
    }

    pub fn label_remove(&self, identity: &str, label: &str) -> Result<()> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached("DELETE FROM tns_labels WHERE identity = ?1 AND label = ?2")
            .map_err(sqlite_err)?;
        stmt.execute(params![identity, label]).map_err(sqlite_err)?;
        Ok(())
    }

    pub fn label_list(&self, identity: &str) -> Result<Vec<(String, Vec<Vec<u8>>, bool)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT l.label, l.publish, r.record
                 FROM tns_labels l
                 LEFT JOIN tns_records r ON r.identity = l.identity AND r.label = l.label
                 WHERE l.identity = ?1
                 ORDER BY l.label",
            )
            .map_err(sqlite_err)?;
        let mapped = stmt
            .query_map(params![identity], |row| {
                let label: String = row.get(0)?;
                let publish: i32 = row.get(1)?;
                let record: Option<Vec<u8>> = row.get(2)?;
                Ok((label, publish != 0, record))
            })
            .map_err(sqlite_err)?;
        let rows = mapped
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sqlite_err)?;

        let mut result: Vec<(String, Vec<Vec<u8>>, bool)> = Vec::new();
        for (label, publish, record) in rows {
            if let Some(last) = result.last_mut().filter(|(l, _, _)| l == &label) {
                if let Some(rec) = record {
                    last.1.push(rec);
                }
            } else {
                let records = record.map_or_else(Vec::new, |r| vec![r]);
                result.push((label, records, publish));
            }
        }
        Ok(result)
    }

    // ── Zone published record map (TNS zone-root source of truth) ──
    //
    // The authoritative set of records a zone publishes, keyed by the zone's
    // ServiceId so EVERY publisher path (user labels, hidden-service intro/peer)
    // funnels into one place. The zone root is rebuilt and re-signed from this
    // map on every change; `records` is a serialized TnsRecord set for one label.

    /// Upsert the record set for `label` in zone `zone_sid`.
    pub fn zone_record_set(&self, zone_sid: &[u8; 32], label: &str, records: &[u8]) -> Result<()> {
        let conn = self.lock()?;
        conn.prepare_cached(
            "INSERT INTO tns_zone_records(zone_sid, label, records) VALUES(?1, ?2, ?3)
             ON CONFLICT(zone_sid, label) DO UPDATE SET records = excluded.records",
        )
        .map_err(sqlite_err)?
        .execute(params![zone_sid.as_slice(), label, records])
        .map_err(sqlite_err)?;
        Ok(())
    }

    /// Remove `label` from zone `zone_sid`. No-op if absent.
    pub fn zone_record_remove(&self, zone_sid: &[u8; 32], label: &str) -> Result<()> {
        let conn = self.lock()?;
        conn.prepare_cached("DELETE FROM tns_zone_records WHERE zone_sid = ?1 AND label = ?2")
            .map_err(sqlite_err)?
            .execute(params![zone_sid.as_slice(), label])
            .map_err(sqlite_err)?;
        Ok(())
    }

    /// All `(label, serialized records)` published in zone `zone_sid`, ordered by label.
    pub fn zone_record_list(&self, zone_sid: &[u8; 32]) -> Result<Vec<(String, Vec<u8>)>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare_cached(
                "SELECT label, records FROM tns_zone_records WHERE zone_sid = ?1 ORDER BY label",
            )
            .map_err(sqlite_err)?;
        let rows = stmt
            .query_map(params![zone_sid.as_slice()], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sqlite_err)?;
        rows.collect::<rusqlite::Result<Vec<_>>>().map_err(sqlite_err)
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

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Columns of `dht_records`, in order.
const DHT_RECORD_COLUMNS: [&str; 11] = [
    "key",
    "signer",
    "record_type",
    "sequence",
    "ttl_secs",
    "expires_at_unix",
    "source",
    "value",
    "signature",
    "signer_algo",
    "signer_pubkey",
];

/// Create `dht_records`, or recreate it if its columns differ. The table is a
/// cache of records their owners republish, so a layout change drops it
/// rather than migrating it. One row per (key, signer): every record type
/// keeps at most one version per signer at a key, and unsigned content (zero
/// signer) is self-certifying, one valid blob per key.
fn ensure_dht_records_table(conn: &Connection) -> rusqlite::Result<()> {
    let columns: Vec<String> = conn
        .prepare("PRAGMA table_info(dht_records)")?
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<_>>()?;
    if !columns.is_empty() && columns.iter().map(String::as_str).ne(DHT_RECORD_COLUMNS) {
        conn.execute_batch("DROP TABLE dht_records")?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS dht_records (
             key BLOB NOT NULL,
             signer BLOB NOT NULL,
             record_type INTEGER NOT NULL,
             sequence INTEGER NOT NULL,
             ttl_secs INTEGER NOT NULL,
             expires_at_unix INTEGER NOT NULL,
             source BLOB,
             value BLOB NOT NULL,
             signature BLOB NOT NULL,
             signer_algo INTEGER NOT NULL,
             signer_pubkey BLOB NOT NULL,
             PRIMARY KEY (key, signer)
         );",
    )
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
        assert_eq!(
            db.get_metadata("signed_content_sequence").unwrap(),
            Some(11)
        );

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
            expires_at_unix: unix_now_secs() + 42,
            source: None,
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
        db.label_set("", "alice", &[zone_rec.clone()], false)
            .unwrap();
        let result = db.label_get("", "alice").unwrap();
        assert!(result.is_some());
        let (blobs, publish) = result.unwrap();
        assert_eq!(blobs, vec![zone_rec]);
        assert!(!publish);
        let list = db.label_list("").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "alice");
        db.label_remove("", "alice").unwrap();
        assert!(db.label_get("", "alice").unwrap().is_none());

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
            expires_at_unix: unix_now_secs() + 100,
            source: None,
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
    fn dht_content_records_are_one_per_key() {
        let path = temp_db_path("dht-content-candidates");
        let db = StateDb::open(&path).unwrap();
        let key = [9u8; 64];
        let signer = [0u8; 32];

        for (seq, value) in [(0u64, b"first".to_vec()), (0u64, b"second".to_vec())] {
            let record = PersistedRecord {
                key,
                record_type: RecordType::Content.as_u8(),
                sequence: seq,
                signer,
                ttl_secs: 100,
                expires_at_unix: unix_now_secs() + 100,
                source: None,
                value,
                signature: Vec::new(),
                signer_algo: 0,
                signer_pubkey: Vec::new(),
            };
            db.upsert_dht_record(&record).unwrap();
        }

        // One row per (key, signer): content is self-certifying, one valid
        // blob per key, so a second blob replaces the row.
        let loaded = db.load_dht_records().unwrap();
        assert_eq!(loaded.len(), 1);
        cleanup(&path);
    }

    #[test]
    fn dht_expired_records_not_loaded() {
        let path = temp_db_path("dht-expired");
        let db = StateDb::open(&path).unwrap();
        let key = [7u8; 64];
        let signer = [8u8; 32];
        let record = PersistedRecord {
            key,
            record_type: RecordType::Content.as_u8(),
            sequence: 0,
            signer,
            ttl_secs: 1,
            expires_at_unix: unix_now_secs().saturating_sub(1),
            source: None,
            value: b"expired".to_vec(),
            signature: Vec::new(),
            signer_algo: 0,
            signer_pubkey: Vec::new(),
        };
        db.upsert_dht_record(&record).unwrap();

        assert!(db.load_dht_records().unwrap().is_empty());
        db.delete_expired_dht_records().unwrap();
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
        use crate::identity::{self, peer_id_from_signing_pubkey, Keypair};
        use crate::wire::DhtPutMsg;
        use tarnet_api::types::SigningAlgo;

        let kp = Keypair::generate_classic();
        let peer_id = kp.peer_id();
        let signer = peer_id;
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
            walk: Default::default(),
        };
        put.signature = kp.sign(&put.signable_bytes());

        assert!(identity::verify_signed(
            identity::SignedBy::Peer(&put.signer),
            Some(put.signer_algo),
            &put.signer_pubkey,
            &put.signable_bytes(),
            &put.signature
        ));

        let record = DhtRecord {
            key: crate::types::DhtId(key),
            record_type: RecordType::Hello,
            sequence: 1,
            signer,
            signer_algo: put.signer_algo,
            signer_pubkey: put.signer_pubkey.clone(),
            value: value.clone(),
            expires: crate::dht::expires_in(Duration::from_secs(600)),
            stored_at: Instant::now(),
            signature: put.signature.clone(),
        };
        let persisted = PersistedRecord::from_stored(&record, RecordSource::Local).unwrap();
        let path = temp_db_path("sig-verify");
        let db = StateDb::open(&path).unwrap();
        db.upsert_dht_record(&persisted).unwrap();

        let loaded_records = db.load_dht_records().unwrap();
        let loaded = loaded_records[0].clone().into_stored().unwrap().0;

        let forwarded_put = DhtPutMsg {
            key: *loaded.key.as_bytes(),
            record_type: loaded.record_type,
            sequence: loaded.sequence,
            signer: loaded.signer,
            ttl: loaded.remaining_ttl().as_secs() as u32,
            value: loaded.value.clone(),
            signature: loaded.signature.clone(),
            signer_algo: loaded.signer_algo,
            signer_pubkey: loaded.signer_pubkey.clone(),
            walk: Default::default(),
        };

        let algo = SigningAlgo::from_u8(forwarded_put.signer_algo).unwrap();
        assert!(
            !forwarded_put.signer_pubkey.is_empty(),
            "signer_pubkey must survive persistence"
        );
        let expected_peer = peer_id_from_signing_pubkey(&forwarded_put.signer_pubkey);
        assert_eq!(
            expected_peer,
            forwarded_put.signer,
            "signer_pubkey must match signer PeerId"
        );
        assert!(
            identity::verify_signed(
                identity::SignedBy::Peer(&forwarded_put.signer),
                Some(algo as u8),
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
