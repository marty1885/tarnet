use super::*;
use crate::dht::VerifiedRecord;
use crate::types::ContentHandle;

/// What launching DHT walks needs.
#[derive(Clone)]
pub(crate) struct DhtWalker {
    pub(super) local: PeerId,
    pub(super) links: Arc<Mutex<LinkTable>>,
    pub(super) routing_table: Arc<Mutex<RoutingTable>>,
    /// Neighbours' `DhtNeighbor` store flags; missing means "assume it stores".
    pub(super) neighbor_stores: Arc<Mutex<HashMap<PeerId, bool>>>,
    pub(super) query_tokens: Arc<std::sync::Mutex<QueryTokens>>,
    pub(super) sender: super::sender::Sender,
}

/// A GET walk we issued or relayed: where its responses go back to, and the
/// key it asked for. A response for any other key under the token is
/// dropped, so whoever saw a token can't use it to write other keys into the
/// originator's store.
pub(crate) struct QueryToken {
    pub(super) prev: PeerId,
    pub(super) key: [u8; 64],
    /// The neighbours we passed the walk to (once per visit): responses come
    /// back only from them. Empty if the walk ended here.
    pub(super) next: Vec<PeerId>,
}

/// Hard ceiling on reverse-path state, for GETs we relay and GETs we launch
/// alike. Per-peer admission in the governor is the first control; this cap
/// is the final global invariant, enforced by the table itself.
pub(super) const MAX_QUERY_TOKENS: usize = 65_536;
/// How long a query token lives.
pub(super) const QUERY_TOKEN_TTL: Duration = Duration::from_secs(30);
/// Visits of one GET walk a node forwards. Walks revisit a node only in
/// their random phase or right after it, so a few is plenty.
const MAX_GET_VISITS: usize = 4;

/// The reverse-path table: query token → where responses go and the key
/// asked for.
pub(crate) type QueryTokens = crate::bounded::BoundedMap<[u8; 32], QueryToken>;

/// Watch walks are relaunched this often by the watcher.
pub(super) const WATCH_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
/// Registrations along a watch walk last two relaunch periods: one lost
/// relaunch doesn't drop the watch, and old walks expire instead of piling up.
const WATCH_REGISTRATION: Duration = Duration::from_secs(2 * 60);

impl DhtWalker {
    pub(super) async fn neighbors(&self) -> Vec<DhtNeighbor> {
        let peers: Vec<PeerId> = self.links.lock().await.iter().map(|(p, _)| *p).collect();
        let stores = self.neighbor_stores.lock().await;
        peers
            .into_iter()
            .map(|p| DhtNeighbor::new(p, stores.get(&p).copied().unwrap_or(true)))
            .collect()
    }

    /// First hops for one round of walks (ρ of them, for the estimated
    /// network size and our degree): distinct random neighbours, cycling once
    /// every neighbour has one. Empty without links.
    pub(super) async fn first_hops(&self) -> Vec<PeerId> {
        use rand::seq::SliceRandom;
        let mut peers: Vec<PeerId> = self.links.lock().await.iter().map(|(p, _)| *p).collect();
        if peers.is_empty() {
            return Vec::new();
        }
        let n = self.routing_table.lock().await.network_size_estimate();
        let count = crate::dht::walk_count(n, peers.len());
        peers.shuffle(&mut rand::thread_rng());
        (0..count).map(|i| peers[i % peers.len()]).collect()
    }

    /// Send one round of PUT walks for `put`.
    pub(super) async fn launch_put(&self, put: &DhtPutMsg) {
        let deadline = Instant::now() + Duration::from_secs(put.ttl as u64);
        let encoded = put.to_wire().encode();
        let walks = self.first_hops().await.into_iter().map(|p| (p, encoded.clone())).collect();
        self.sender.batch_until(walks, deadline).await;
    }

    /// Launch one round of GET walks for `key`, each under a fresh query token
    /// registered with us as originator and with `search` before any walk
    /// leaves, so no fast reply is missed. Only as many walks leave as there
    /// are tokens the table admits: with the reverse-path table full, fewer
    /// (or none) are launched.
    pub(super) async fn launch_get(
        &self,
        key: &[u8; 64],
        search: (&Arc<SearchRegistry>, &mpsc::Sender<VerifiedRecord>),
        deadline: Instant,
    ) -> SearchRound {
        // Outbound work may not outlive either the search or the reverse path
        // authorizing its responses.
        let send_deadline = deadline.min(Instant::now() + QUERY_TOKEN_TTL);
        let hops = self.first_hops().await;
        let count = hops.len();
        // Each token remembers the first hop it leaves through: responses
        // under it are taken only from there.
        let walks: Vec<([u8; 32], PeerId)> = {
            let mut qt = self.query_tokens.lock().unwrap();
            hops.into_iter()
                .map(|hop| (random_token(), hop))
                .filter(|(t, hop)| {
                    qt.try_insert(
                        *t,
                        QueryToken {
                            prev: self.local,
                            key: *key,
                            next: vec![*hop],
                        },
                    )
                    .is_ok()
                })
                .collect()
        };
        if walks.len() < count {
            log::debug!("DHT GET state full: launching {} of {} walks", walks.len(), count);
        }
        let tokens: Vec<[u8; 32]> = walks.iter().map(|(t, _)| *t).collect();
        {
            let (registry, tx) = search;
            let mut reg = registry.lock().unwrap();
            for t in &tokens {
                reg.insert(*t, tx.clone());
            }
        }
        let mut registration = SearchRound {
            registry: search.0.clone(),
            query_tokens: self.query_tokens.clone(),
            tokens,
            task: None,
        };
        let msgs = walks
            .into_iter()
            .map(|(token, hop)| {
                let get = DhtGetMsg {
                    walk: WalkHeader::origin(),
                    key: *key,
                    query_token: token,
                };
                (hop, get.to_wire().encode())
            })
            .collect();
        let sender = self.sender.clone();
        registration.task = Some(tokio::spawn(async move {
            sender.batch_until(msgs, send_deadline).await;
        }));
        registration
    }
}

pub(super) type SearchRegistry = std::sync::Mutex<HashMap<[u8; 32], mpsc::Sender<VerifiedRecord>>>;

/// Own all resources of one locally launched round. Cancellation has one
/// synchronous boundary, including when the enclosing launch is cancelled.
#[must_use = "dropping the round cancels its walks and releases its registrations"]
pub(super) struct SearchRound {
    registry: Arc<SearchRegistry>,
    query_tokens: Arc<std::sync::Mutex<QueryTokens>>,
    tokens: Vec<[u8; 32]>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl SearchRound {
    pub(super) fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

impl Drop for SearchRound {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let mut registry = self.registry.lock().unwrap();
        let mut queries = self.query_tokens.lock().unwrap();
        for token in &self.tokens {
            registry.remove(token);
            queries.remove(token);
        }
    }
}

fn random_token() -> [u8; 32] {
    let mut t = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut t);
    t
}

/// Signers whose newest version a local watch remembers handing the app.
/// Past this, a new signer's records are still delivered, just not tracked.
const MAX_TOLD_SIGNERS: usize = 256;

/// A key this node watches.
pub(super) struct LocalWatch {
    task: Option<tokio::task::JoinHandle<()>>,
    pub(super) expires_at: Instant,
    /// Every live walk's token, its first hop, and registration deadline.
    /// Notifications come only from that hop until that deadline.
    tokens: Vec<([u8; 32], PeerId, Instant)>,
    last_round: Option<Instant>,
    /// Newest sequence handed to the app, per signer: the app hears of each
    /// version once, however many walks report it, and never of an older one.
    told: HashMap<PeerId, u64>,
}

impl LocalWatch {
    fn new(expires_at: Instant) -> Self {
        Self {
            task: None,
            expires_at,
            tokens: Vec::new(),
            last_round: None,
            told: HashMap::new(),
        }
    }

    fn live(&self) -> bool {
        self.expires_at > Instant::now()
    }

    fn owns(&self, token: &[u8; 32], from: &PeerId) -> bool {
        self.tokens
            .iter()
            .any(|(t, peer, expires)| t == token && peer == from && *expires > Instant::now())
    }

    fn new_round(&mut self, tokens: Vec<([u8; 32], PeerId)>, lifetime: Duration) -> bool {
        let now = Instant::now();
        self.tokens.retain(|(_, _, expires)| *expires > now);
        // Limit overlap, but allow a short subscription to be extended
        // before its old registrations expire. Never discard a live path.
        let covered = self
            .tokens
            .iter()
            .any(|(_, _, expires)| *expires >= now + WATCH_REFRESH_INTERVAL);
        if tokens.is_empty()
            || self.tokens.len() + tokens.len() > 4 * crate::dht::MAX_WALKS
            || (covered
                && self
                    .last_round
                    .is_some_and(|at| at.elapsed() < Duration::from_secs(30)))
        {
            return false;
        }
        self.tokens.extend(
            tokens
                .into_iter()
                .map(|(t, peer)| (t, peer, now + lifetime)),
        );
        self.last_round = Some(now);
        true
    }

    /// Whether `signer`'s `sequence` is news to the app (and now told).
    fn news(&mut self, signer: &PeerId, sequence: u64) -> bool {
        match self.told.get_mut(signer) {
            Some(told) if *told >= sequence => false,
            Some(told) => {
                *told = sequence;
                true
            }
            None => {
                if self.told.len() < MAX_TOLD_SIGNERS {
                    self.told.insert(*signer, sequence);
                }
                true
            }
        }
    }
}

impl Drop for LocalWatch {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Node {
    /// Next routing step for a walk this node received from `from`.
    async fn dht_walk_step(&self, key: &DhtId, header: &WalkHeader, from: &PeerId) -> WalkStep {
        let neighbors = self.dht_walker.neighbors().await;
        crate::dht::walk_step(
            &self.peer_id(),
            self.dht_stores,
            key,
            header,
            from,
            &neighbors,
            &mut rand::thread_rng(),
        )
    }

    // ── Walk handlers ──

    pub(super) async fn handle_dht_put(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut put = DhtPutMsg::from_bytes(payload)?;
        let key = DhtId(put.key);
        // `ttl` is unsigned: never store or forward more than the per-type
        // ceiling, whatever the sender claimed.
        put.ttl = crate::dht::clamp_ttl_secs(put.record_type, put.ttl);

        match self.dht_walk_step(&key, &put.walk, &from).await {
            WalkStep::Forward(next, walk) => {
                // Nodes on the way neither verify nor store: only the end of
                // the walk does. Watchers here still hear of it.
                put.walk = walk;
                if let Err(e) = self.send_to_peer_deferred(&next, &put.to_wire().encode()).await {
                    log::debug!("DHT PUT forward to {:?} failed: {}", next, e);
                }
                self.dht_put_seen(&put, None, Some(&from)).await;
            }
            WalkStep::End => {
                let record = match VerifiedRecord::from_put_msg(&put) {
                    Ok(verified) => verified,
                    Err(reason) => {
                        log::warn!("DHT PUT from {:?}: {}, dropping", from, reason);
                        return Ok(());
                    }
                };
                self.dht_store
                    .lock()
                    .await
                    .put_record(record.clone(), RecordSource::Peer(from));
                self.dht_put_seen(&put, Some(record), Some(&from)).await;
            }
            WalkStep::Drop => {
                log::debug!("DHT PUT walk from {:?} has nowhere to go", from);
            }
        }
        Ok(())
    }

    pub(super) async fn handle_dht_get(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut get = DhtGetMsg::from_bytes(payload)?;
        let key = DhtId(get.key);

        // The first visit of a walk records where its responses go back
        // (`prev`) and is answered. A walk may pass here again and travels on
        // from here each time, but its responses always follow the first
        // visit's `prev`: a node can't be its own predecessor's predecessor,
        // so replies walk a tree rooted at the originator and can't loop.
        // Checked and added in one step, so the cap holds however dispatch
        // is scheduled.
        let first_visit = {
            let mut qt = self.query_tokens.lock().unwrap();
            let fresh = QueryToken {
                prev: from,
                key: get.key,
                next: Vec::new(),
            };
            match qt.try_insert(get.query_token, fresh) {
                Ok(()) => true,
                // The same walk again, unless someone reuses its token for
                // another key.
                Err(crate::bounded::Refused::Duplicate) => {
                    if qt.get(&get.query_token).map_or(true, |t| t.key != get.key) {
                        return Ok(());
                    }
                    false
                }
                Err(crate::bounded::Refused::Full) => {
                    log::debug!("Global DHT GET state limit reached");
                    return Ok(());
                }
            }
        };

        if first_visit {
            self.answer_dht_get(&from, &get).await;
        }

        if let WalkStep::Forward(next, walk) = self.dht_walk_step(&key, &get.walk, &from).await {
            // Responses relayed back come only from where it went.
            {
                let mut qt = self.query_tokens.lock().unwrap();
                let Some(t) = qt.get_mut(&get.query_token) else {
                    return Ok(());
                };
                if t.next.len() >= MAX_GET_VISITS {
                    return Ok(());
                }
                t.next.push(next);
            }
            get.walk = walk;
            if let Err(e) = self.send_to_peer_deferred(&next, &get.to_wire().encode()).await {
                log::debug!("DHT GET forward to {:?} failed: {}", next, e);
            }
        }
        Ok(())
    }

    /// Answer a GET with the records held here, along the reverse path. The
    /// response must fit one message: owner-bound records (the zone root /
    /// hello the key exists for) go first, then a random sample of the rest,
    /// skipping any that would overflow. Junk piled onto a key can then never
    /// push the real record out of the reply or make the reply unsendable.
    async fn answer_dht_get(&self, to: &PeerId, get: &DhtGetMsg) {
        let records: Vec<DhtResponseRecord> = {
            use rand::seq::SliceRandom;
            let store = self.dht_store.lock().await;
            let mut records = store.get(&DhtId(get.key));
            records.shuffle(&mut rand::thread_rng());
            records.sort_by_key(|r| !matches!(r.record_type, RecordType::Hello | RecordType::ZoneRoot));
            let mut size = 32 + 64 + 2; // token + key + count
            let mut out = Vec::new();
            for r in records {
                // Every signed field (incl. the signer pubkey the requester
                // must verify against) and the remaining TTL.
                let rec = r.to_response_record();
                let rec_len = rec.to_bytes().len();
                if size + rec_len > MAX_PAYLOAD {
                    continue;
                }
                size += rec_len;
                out.push(rec);
            }
            out
        };
        if records.is_empty() {
            return;
        }
        let response = DhtGetResponseMsg {
            query_token: get.query_token,
            key: get.key,
            records,
        };
        // A failed reply must not stop the query from travelling on.
        if let Err(e) = self.send_to_peer_deferred(to, &response.to_wire().encode()).await {
            log::debug!("DHT GET reply to {:?} failed: {}", to, e);
        }
    }

    pub(super) async fn handle_dht_get_response(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut resp = DhtGetResponseMsg::from_bytes(payload)?;
        for rec in &mut resp.records {
            rec.ttl = crate::dht::clamp_ttl_secs(rec.record_type, rec.ttl);
        }

        // Only responses to a query we issued or relayed, for the key it
        // asked, from where the walk went, are accepted.
        let prev_hop = self
            .query_tokens
            .lock().unwrap()
            .get(&resp.query_token)
            .filter(|t| t.key == resp.key && t.next.contains(&from))
            .map(|t| t.prev);
        let Some(prev) = prev_hop else {
            log::debug!("DhtGetResponse with unknown query_token, another key, or not from where the walk went, from {:?}, dropping", from);
            return Ok(());
        };

        if prev != self.peer_id() {
            // Relay toward the originator, who verifies. Relays don't keep
            // anything: holding results for someone else's lookup only
            // records what passed through.
            return self.send_to_peer_deferred(&prev, &resp.to_wire().encode()).await;
        }

        // Ours: verified records go to the search that asked. Nothing is
        // stored: the store holds what walks placed here, and our own.
        let tx = self.dht_searches.lock().unwrap().get(&resp.query_token).cloned();
        let Some(tx) = tx else {
            return Ok(());
        };
        let resp_key = DhtId(resp.key);
        for rec in &resp.records {
            match VerifiedRecord::from_response_record(resp_key, rec) {
                Ok(verified) => {
                    let _ = tx.try_send(verified);
                }
                Err(reason) => {
                    log::warn!("DhtGetResponse from {:?}: {}, dropping record", from, reason);
                }
            }
        }
        Ok(())
    }

    pub(super) async fn handle_dht_watch(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut watch = DhtWatchMsg::from_bytes(payload)?;
        let key = DhtId(watch.key);
        {
            let mut watches = self.dht_watches.lock().await;
            if watch.expiration_secs == 0 {
                watches.set_watch(watch.key, watch.query_token, from, 0);
                return Ok(());
            }
            // A walk revisiting us must not re-point the return path (it
            // would loop back through the later hops).
            if watches.has_token(&watch.key, &watch.query_token) {
                return Ok(());
            }
            if !watches.set_watch(watch.key, watch.query_token, from, watch.expiration_secs) {
                log::debug!("DHT watch from {:?} refused (cap)", from);
                return Ok(());
            }
        }
        if let WalkStep::Forward(next, walk) = self.dht_walk_step(&key, &watch.walk, &from).await {
            // Notifications relayed back come only from where it went.
            self.dht_watches
                .lock()
                .await
                .set_next(&watch.key, &watch.query_token, next);
            watch.walk = walk;
            let _ = self.send_to_peer_deferred(&next, &watch.to_wire().encode()).await;
        }
        Ok(())
    }

    pub(super) async fn handle_dht_watch_notify(&self, from: PeerId, payload: &[u8]) -> Result<()> {
        let mut notify = DhtWatchNotifyMsg::from_bytes(payload)?;
        notify.put.ttl = crate::dht::clamp_ttl_secs(notify.put.record_type, notify.put.ttl);

        let ours = self
            .local_watches
            .lock()
            .await
            .get(&notify.put.key)
            .is_some_and(|w| w.live() && w.owns(&notify.query_token, &from));
        if ours {
            match VerifiedRecord::from_put_msg(&notify.put) {
                Ok(record) => self.tell_app(record).await,
                Err(reason) => log::warn!("DhtWatchNotify from {:?}: {}, dropping", from, reason),
            }
            return Ok(());
        }
        // Relay back along the watch walk without verifying; the watcher
        // verifies.
        let prev_hop = self
            .dht_watches
            .lock()
            .await
            .relay_for(&notify.put.key, &notify.query_token, &from);
        match prev_hop {
            Some(prev) => self.send_to_peer_deferred(&prev, &notify.to_wire().encode()).await,
            None => {
                log::debug!("DhtWatchNotify with unknown query_token, or not from where the watch went, dropping");
                Ok(())
            }
        }
    }

    /// A PUT for `put.key` passed through or ended here, or we published it:
    /// tell the watchers registered here (other than via `from`) and, if we
    /// watch the key ourselves, the app. Each hears only of versions it
    /// hasn't been told, so the ρ walks of one PUT and an owner's republishes
    /// tell nobody twice.
    pub(super) async fn dht_put_seen(&self, put: &DhtPutMsg, verified: Option<VerifiedRecord>, from: Option<&PeerId>) {
        let remote = self.dht_watches.lock().await.is_watched(&put.key);
        let local = self
            .local_watches
            .lock()
            .await
            .get(&put.key)
            .is_some_and(|w| w.live());
        if !remote && !local {
            return;
        }
        // Verify first, even as a relay: what we notify is remembered as
        // told, so a forged record claiming a victim's signer and a huge
        // sequence would otherwise suppress the victim's real news.
        let record = match verified {
            Some(r) => r,
            None => match VerifiedRecord::from_put_msg(put) {
                Ok(r) => r,
                Err(_) => return,
            },
        };
        if record.record().is_expired() {
            return;
        }
        if remote {
            let watchers = self
                .dht_watches
                .lock()
                .await
                .watchers_needing_news(&put.key, put.signer.as_bytes(), put.sequence);
            for (token, via_peer) in watchers {
                if Some(&via_peer) == from {
                    continue;
                }
                let notify = DhtWatchNotifyMsg {
                    query_token: token,
                    put: put.clone(),
                };
                if self
                    .send_to_peer_deferred(&via_peer, &notify.to_wire().encode())
                    .await
                    .is_ok()
                {
                    self.dht_watches.lock().await.mark_notified(
                        &put.key,
                        &token,
                        &via_peer,
                        put.signer.as_bytes(),
                        put.sequence,
                    );
                }
            }
        }
        if local {
            self.tell_app(record).await;
        }
    }

    /// Hand a record for a key we watch to the app, if it is news to it.
    async fn tell_app(&self, record: VerifiedRecord) {
        let r = record.into_inner();
        if r.is_expired() {
            return;
        }
        let mut watches = self.local_watches.lock().await;
        let Some(w) = watches.get_mut(r.key.as_bytes()).filter(|w| w.live()) else {
            return;
        };
        if w.told.get(&r.signer).is_some_and(|seq| *seq >= r.sequence) {
            return;
        }
        let signer = r.signer;
        let sequence = r.sequence;
        if self.dht_watch_tx.try_send((r.key, r)).is_ok() {
            w.news(&signer, sequence);
        } else {
            log::debug!("DHT watch application queue full or closed; notification dropped");
        }
    }

    // ── Publishing ──

    /// Republish the records this node signed itself, and unsigned content
    /// it published. Owners republishing is what keeps records alive; there
    /// is no replication sweep. Hellos have their own timer, and records
    /// signed by any other key (identities, zones, disposable label keys)
    /// are republished by their owners' own timers. That keeps a Hidden
    /// identity's records out of this republish, which runs on link-up and
    /// alongside the node's own records: a watcher could otherwise open a
    /// link to a suspected host and see the hidden service's re-PUT follow.
    pub(crate) async fn dht_republish_own(&self) {
        let records = self.own_records_to_republish().await;
        for record in &records {
            self.dht_walker.launch_put(&record.to_put_msg()).await;
        }
        if !records.is_empty() {
            log::debug!("Republished {} own DHT records", records.len());
        }
    }

    /// The records [`dht_republish_own`](Self::dht_republish_own) sends.
    pub(super) async fn own_records_to_republish(&self) -> Vec<DhtRecord> {
        let me = self.peer_id();
        self.dht_store
            .lock()
            .await
            .own_records()
            .into_iter()
            .filter(|r| match r.record_type {
                RecordType::Hello => false,
                RecordType::Content => true,
                _ => r.signer == me,
            })
            .cloned()
            .collect()
    }

    /// Next monotonic sequence for signed-content / signed-at-key records,
    /// persisted so it survives restart.
    async fn next_signed_content_sequence(&self) -> u64 {
        let mut seq = self.signed_content_sequence.lock().await;
        *seq += 1;
        let sequence = *seq;
        self.db_set_metadata("signed_content_sequence", sequence);
        sequence
    }

    /// The single publish path: store a freshly-minted record locally (and
    /// so in the database), tell watchers, and send ρ PUT walks. The
    /// `DhtPutMsg` is *derived* from the record, never built in parallel, so
    /// the wire copy and the stored copy can't drift.
    pub(crate) async fn dht_publish(&self, record: VerifiedRecord) -> Result<()> {
        // A record too large to store is too large to send: say so rather
        // than send a PUT nobody keeps.
        let max = self.dht_store.lock().await.limits().max_value_bytes;
        if record.record().value.len() > max {
            return Err(Error::Protocol(format!(
                "DHT record value of {} bytes exceeds {}",
                record.record().value.len(),
                max
            )));
        }
        let put = record.record().to_put_msg();
        let outcome = self
            .dht_store
            .lock()
            .await
            .put_record(record.clone(), RecordSource::Local);
        if !outcome.stored {
            return Err(Error::Protocol(
                "DHT publication refused by storage admission".into(),
            ));
        }
        self.dht_put_seen(&put, Some(record), None).await;
        self.dht_walker.launch_put(&put).await;
        Ok(())
    }

    /// Content-addressed DHT put: stores locally and sends PUT walks.
    /// Returns the content handle (64 bytes) needed for retrieval.
    pub async fn dht_put_content(&self, value: &[u8]) -> Result<ContentHandle> {
        let (record, handle) = VerifiedRecord::new_content(value, Duration::from_secs(3600));
        self.dht_publish(record).await?;
        // Not the handle itself: its first half decrypts the content.
        log::info!("DHT content put at {:?}", crate::dht::content_key(&handle));
        Ok(handle)
    }

    /// Signed content-addressed DHT put: the value is encrypted under its own
    /// hash (storage nodes see an opaque blob), signed, and published. Each
    /// signer's record at a content key is kept independently. Returns the
    /// content handle needed for retrieval.
    pub async fn dht_put_signed_content(&self, value: &[u8], ttl_secs: u32) -> Result<ContentHandle> {
        let sequence = self.next_signed_content_sequence().await;
        let (record, inner_hash) = VerifiedRecord::new_signed_content(
            &self.identity,
            value,
            sequence,
            Duration::from_secs(ttl_secs as u64),
        );
        self.dht_publish(record).await?;
        log::info!("DHT signed content put");
        Ok(inner_hash)
    }

    /// Next monotonic, restart-persisted sequence for signed-at-key records.
    /// Callers that must embed the sequence in a value *before* publishing (the
    /// TNS/pool self-authenticating bundle signs over it) take it here and pass
    /// it back into [`dht_put_signed_at_key`], so both layers agree on it.
    pub async fn next_dht_sequence(&self) -> u64 {
        self.next_signed_content_sequence().await
    }

    /// Store signed content at an arbitrary DHT key (not content-addressed).
    /// `signer_keypair` is the *disposable* per-label key (not the zone master);
    /// `value` is stored verbatim (the caller seals it); `sequence` must be the
    /// same value the caller bound into `value`.
    pub async fn dht_put_signed_at_key(
        &self,
        signer_keypair: &crate::identity::Keypair,
        key: DhtId,
        value: &[u8],
        sequence: u64,
        ttl_secs: u32,
    ) -> Result<()> {
        let record = VerifiedRecord::new_signed_at_key(
            signer_keypair,
            key,
            value,
            sequence,
            Duration::from_secs(ttl_secs as u64),
        );
        self.dht_publish(record).await?;
        log::info!("TNS signed put at key {:?}", key);
        Ok(())
    }

    /// Publish a self-addressed TNS zone root: signed by the zone key at
    /// `zone_root_key(zone_sid)`. Only the zone owner can write there (the ingest
    /// gate enforces it), so the location carries no foreign-signer flood surface.
    /// `value` is the caller's already-sealed root blob, stored verbatim.
    pub async fn dht_put_zone_root(
        &self,
        zone_keypair: &crate::identity::Keypair,
        value: &[u8],
        sequence: u64,
        ttl_secs: u32,
    ) -> Result<()> {
        let record = VerifiedRecord::new_zone_root(
            zone_keypair,
            value,
            sequence,
            Duration::from_secs(ttl_secs as u64),
        );
        self.dht_publish(record).await?;
        log::info!("TNS zone root put for {:?}", zone_keypair.identity.service_id());
        Ok(())
    }

    /// Update one label in an owned zone's published working set
    /// (`label → serialized TnsRecord set`). Returns whether it changed.
    ///
    /// The working set lives in memory. It starts as the zone's local labels
    /// marked published (the label table is where persistent names live);
    /// everything else in it belongs to a live publisher — the identity's
    /// own `peer` or `intro` label, or a label a client published for as long
    /// as it stays connected — and is put back by that publisher after a
    /// restart, or not at all.
    ///
    pub(crate) async fn zone_published_update(
        &self,
        zone_sid: &tarnet_api::types::ServiceId,
        label: &str,
        records: Option<Vec<u8>>,
    ) -> bool {
        let mut map = self.zone_published.lock().await;
        if !map.contains_key(zone_sid) {
            let loaded = self.published_labels(zone_sid).await;
            map.insert(*zone_sid, loaded);
        }
        let entry = map.get_mut(zone_sid).expect("loaded above");
        match records {
            Some(blob) => entry.insert(label.to_string(), blob.clone()).as_ref() != Some(&blob),
            None => entry.remove(label).is_some(),
        }
    }

    /// The zone's working set to sign, with a fresh sequence. Both are taken
    /// under one lock, so a higher sequence always carries a same-or-newer
    /// set: concurrent publishers (a hidden service's "intro" and a user
    /// label) can't invert.
    pub(crate) async fn zone_signing_snapshot(
        &self,
        zone_sid: &tarnet_api::types::ServiceId,
    ) -> (std::collections::BTreeMap<String, Vec<u8>>, u64) {
        let mut map = self.zone_published.lock().await;
        if !map.contains_key(zone_sid) {
            let loaded = self.published_labels(zone_sid).await;
            map.insert(*zone_sid, loaded);
        }
        let snapshot = map[zone_sid].clone();
        let sequence = self.next_signed_content_sequence().await;
        (snapshot, sequence)
    }

    /// The zone's local labels marked published, as a working set.
    async fn published_labels(
        &self,
        zone_sid: &tarnet_api::types::ServiceId,
    ) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        let Some(db) = &self.db else {
            return out;
        };
        // Labels are filed under the identity's name, or the ServiceId it
        // was named by; the default identity's also under "".
        let mut keys = vec![tarnet_api::types::encode_base32(zone_sid.as_bytes())];
        for (name, sid, ..) in self.list_identities().await {
            if sid == *zone_sid {
                if sid == self.default_service_id().await {
                    keys.push(String::new());
                }
                keys.push(name);
            }
        }
        for key in keys {
            for (label, blobs, publish) in db.label_list(&key).unwrap_or_default() {
                if !publish {
                    continue;
                }
                let records: Vec<crate::tns::TnsRecord> = blobs
                    .iter()
                    .filter_map(|b| crate::tns::tns_record_from_bytes(b).ok().map(|(r, _)| r))
                    .collect();
                out.insert(label, crate::tns::serialize_record_set(&records));
            }
        }
        out
    }

    /// Insert a record directly into the local DHT store, bypassing
    /// propagation. Test-only seam: the only way to place a record on a node
    /// such that a *peer* can obtain it solely via a DhtGet pull.
    #[doc(hidden)]
    pub async fn dht_store_insert_local_for_test(&self, record: crate::dht::DhtRecord) {
        self.dht_store
            .lock()
            .await
            .put(VerifiedRecord::verify_incoming(record).expect("test record must verify"));
    }

    // ── Watching ──

    /// Watch a DHT key for changes until `expiration_secs` passes: watch walks
    /// are relaunched every [`WATCH_REFRESH_INTERVAL`] meanwhile.
    pub async fn dht_watch(&self, key: &DhtId, expiration_secs: u32) {
        let secs = expiration_secs.min(crate::dht::MAX_WATCH_EXPIRATION_SECS);
        if secs == 0 {
            self.dht_unwatch(key).await;
            return;
        }
        let expires_at = Instant::now() + Duration::from_secs(secs as u64);
        {
            let mut watches = self.local_watches.lock().await;
            let watch = watches.entry(*key.as_bytes()).or_insert_with(|| LocalWatch::new(expires_at));
            if expires_at < watch.expires_at {
                if let Some(task) = watch.task.take() {
                    task.abort();
                }
            }
            watch.expires_at = expires_at;
        }
        self.launch_watch_round(key.as_bytes()).await;
        log::debug!("Watching DHT key {:?}", key);
    }

    /// Stop watching a DHT key. Registrations along the walks expire on their
    /// own; notifications that still arrive are dropped here.
    pub async fn dht_unwatch(&self, key: &DhtId) {
        self.local_watches.lock().await.remove(key.as_bytes());
    }

    /// Relaunch watch walks for every live local watch, and drop expired
    /// ones. Paths change with the topology, so watches are kept alive by the
    /// watcher rather than by the nodes on the old path.
    pub(crate) async fn dht_refresh_watches(&self) {
        let keys: Vec<[u8; 64]> = {
            let mut watches = self.local_watches.lock().await;
            watches.retain(|_, w| w.live());
            watches.keys().copied().collect()
        };
        for key in keys {
            self.launch_watch_round(&key).await;
        }
    }

    /// One round of watch walks for `key`, registered as the watch's current
    /// round before any leaves, so no fast notification is missed.
    async fn launch_watch_round(&self, key: &[u8; 64]) {
        let walks: Vec<([u8; 32], PeerId)> = self
            .dht_walker
            .first_hops()
            .await
            .into_iter()
            .map(|hop| (random_token(), hop))
            .collect();
        let mut watches = self.local_watches.lock().await;
        let (secs, deadline) = {
            let Some(w) = watches.get_mut(key).filter(|w| w.live()) else {
                return;
            };
            let secs = w
                .expires_at
                .saturating_duration_since(Instant::now())
                .min(WATCH_REGISTRATION)
                .as_secs()
                .max(1) as u32;
            if !w.new_round(walks.clone(), Duration::from_secs(secs as u64)) {
                return;
            }
            (secs, (Instant::now() + Duration::from_secs(secs as u64)).min(w.expires_at))
        };
        let msgs = walks
            .into_iter()
            .map(|(token, hop)| {
                let watch = DhtWatchMsg {
                    walk: WalkHeader::origin(),
                    key: *key,
                    query_token: token,
                    expiration_secs: secs,
                };
                (hop, watch.to_wire().encode())
            })
            .collect();
        let sender = self.sender.clone();
        let w = watches.get_mut(key).expect("watch held across registration");
        if let Some(task) = w.task.take() {
            task.abort();
        }
        w.task = Some(tokio::spawn(async move {
            sender.batch_until(msgs, deadline).await;
        }));
    }

    /// Take the DHT watch notification receiver.
    pub async fn take_dht_watch_receiver(&self) -> Option<mpsc::Receiver<(DhtId, DhtRecord)>> {
        self.dht_watch_rx.lock().await.take()
    }

    // ── Reading ──

    /// Search the DHT for `key` until `deadline`: a stream of distinct,
    /// verified records, those held here first, then what the walks bring
    /// back. The one way to read the DHT. Dropping the search cancels it.
    ///
    /// Walks find a record only probabilistically, so the search relaunches a
    /// fresh round of walks every [`SEARCH_RELAUNCH_INTERVAL`], up to
    /// [`SEARCH_ROUNDS`] rounds (keys can hold several records, so finding one
    /// does not stop the rounds; dropping the search does).
    pub async fn dht_search(&self, key: DhtId, deadline: Instant) -> DhtSearch {
        let held: VecDeque<VerifiedRecord> = self
            .dht_store
            .lock()
            .await
            .verified_at(&key)
            .into_iter()
            .collect();
        // Bounded: past this many records waiting, responses are dropped.
        let (tx, rx) = mpsc::channel(SEARCH_BUFFER);
        // No time to wait: only what is held here.
        let tokens = if deadline > Instant::now() {
            Some(self.dht_walker
                .launch_get(key.as_bytes(), (&self.dht_searches, &tx), deadline)
                .await)
        } else {
            None
        };
        let rounds_left = if tokens.as_ref().map_or(true, SearchRound::is_empty) {
            SEARCH_ROUNDS
        } else {
            SEARCH_ROUNDS - 1
        };
        DhtSearch {
            held,
            rx,
            tx,
            key,
            rounds: tokens.into_iter().filter(|round| !round.is_empty()).collect(),
            deadline,
            rounds_left,
            next_round: Instant::now() + SEARCH_RELAUNCH_INTERVAL,
            seen: HashSet::new(),
            walker: self.dht_walker.clone(),
            registry: self.dht_searches.clone(),
        }
    }

    /// The records held here at `key` (placed here by walks, or our own),
    /// without searching.
    pub async fn dht_held(&self, key: &DhtId) -> Vec<DhtRecord> {
        self.dht_store.lock().await.get(key).into_iter().cloned().collect()
    }

    /// The plaintext of the content behind `handle`, searched for until
    /// `timeout`.
    pub async fn dht_get_content(&self, handle: &ContentHandle, timeout: Duration) -> Option<Vec<u8>> {
        let key = crate::dht::content_key(handle);
        let mut search = self.dht_search(key, Instant::now() + timeout).await;
        while let Some(rec) = search.next().await {
            if let Ok(plain) = crate::dht::content_address_get(handle, &rec.record().value) {
                return Some(plain);
            }
        }
        None
    }

    /// The signed copies of the content behind `handle`: (signer, plaintext),
    /// everything that has arrived once the first has, searched for until
    /// `timeout`. Records that don't decrypt to it are skipped.
    pub async fn dht_get_signed_content(&self, handle: &ContentHandle, timeout: Duration) -> Vec<(PeerId, Vec<u8>)> {
        let key = crate::dht::content_key(handle);
        let mut search = self.dht_search(key, Instant::now() + timeout).await;
        let mut results: Vec<(PeerId, Vec<u8>)> = Vec::new();
        while let Some(rec) = search.next().await {
            let r = rec.record();
            if r.record_type != RecordType::SignedContent || results.iter().any(|(s, _)| *s == r.signer) {
                continue;
            }
            let Ok(blob) = crate::dht::signed_record_decrypt(&key, &r.value) else {
                continue;
            };
            if let Ok(plain) = crate::dht::content_address_get(handle, &blob) {
                results.push((r.signer, plain));
            }
            if !results.is_empty() && search.is_idle() {
                break;
            }
        }
        results
    }
}

/// Search rounds (initial + relaunches) before a search just waits out its
/// deadline.
const SEARCH_ROUNDS: u32 = 3;
/// Time between search rounds.
const SEARCH_RELAUNCH_INTERVAL: Duration = Duration::from_millis(1500);
/// Records a search buffers before its reader takes them.
const SEARCH_BUFFER: usize = 256;

/// A live DHT search: a stream of distinct verified records for one key (see
/// [`Node::dht_search`]). [`Drop`] deregisters the query tokens, cancelling
/// the search.
pub struct DhtSearch {
    /// Records held here when the search began, yielded first.
    held: VecDeque<VerifiedRecord>,
    rx: mpsc::Receiver<VerifiedRecord>,
    tx: mpsc::Sender<VerifiedRecord>,
    key: DhtId,
    /// Owned rounds keep registrations and outbound tasks alive together.
    rounds: Vec<SearchRound>,
    deadline: Instant,
    rounds_left: u32,
    next_round: Instant,
    /// Records already yielded, so one delivered over several walks is
    /// surfaced once.
    seen: HashSet<(PeerId, u64, RecordType, [u8; 32])>,
    walker: DhtWalker,
    registry: Arc<SearchRegistry>,
}

impl DhtSearch {
    /// Nothing is waiting to be yielded right now.
    pub fn is_idle(&self) -> bool {
        self.held.is_empty() && self.rx.is_empty()
    }

    /// Await the next distinct verified record, or `None` once the deadline
    /// passes.
    pub async fn next(&mut self) -> Option<VerifiedRecord> {
        loop {
            let rec = match self.held.pop_front() {
                Some(rec) => rec,
                None => {
                    let now = Instant::now();
                    if now >= self.deadline {
                        self.rounds.clear();
                        return None;
                    }
                    let relaunch = self.rounds_left > 0;
                    let wake = if relaunch {
                        self.next_round.min(self.deadline)
                    } else {
                        self.deadline
                    };
                    tokio::select! {
                        r = self.rx.recv() => r?,
                        _ = tokio::time::sleep(wake.saturating_duration_since(now)) => {
                            if Instant::now() >= self.deadline {
                                self.rounds.clear();
                                return None;
                            }
                            if relaunch && Instant::now() >= self.next_round {
                                self.next_round = Instant::now() + SEARCH_RELAUNCH_INTERVAL;
                                let tokens = self
                                    .walker
                                    .launch_get(self.key.as_bytes(), (&self.registry, &self.tx), self.deadline)
                                    .await;
                                if !tokens.is_empty() {
                                    self.rounds_left -= 1;
                                    self.rounds.push(tokens);
                                }
                            }
                            continue;
                        }
                    }
                }
            };
            let r = rec.record();
            if r.is_expired() {
                continue;
            }
            let id = (
                r.signer,
                r.sequence,
                r.record_type,
                *blake3::hash(&r.value).as_bytes(),
            );
            if self.seen.insert(id) {
                return Some(rec);
            }
        }
    }
}

#[cfg(test)]
mod lifetime_regressions {
    use super::*;

    #[tokio::test]
    async fn dropping_a_watch_cancels_its_pending_batch() {
        let mut watch = LocalWatch::new(Instant::now() + WATCH_REGISTRATION);
        let task = tokio::spawn(std::future::pending::<()>());
        let cancelled = task.abort_handle();
        watch.task = Some(task);
        drop(watch);
        tokio::task::yield_now().await;
        assert!(cancelled.is_finished());
    }

    #[test]
    fn refresh_keeps_all_unexpired_watch_paths() {
        let peer = PeerId([1; 32]);
        let mut watch = LocalWatch::new(Instant::now() + WATCH_REGISTRATION);
        for token in 0..3 {
            watch.last_round = Instant::now().checked_sub(Duration::from_secs(31));
            assert!(watch.new_round(vec![([token; 32], peer)], WATCH_REGISTRATION));
        }
        assert!(!watch.new_round(vec![([4; 32], peer)], WATCH_REGISTRATION));
        for token in 0..3 {
            assert!(watch.owns(&[token; 32], &peer));
        }
        watch.tokens[0].2 = Instant::now();
        assert!(!watch.owns(&[0; 32], &peer));
    }

    #[test]
    fn cancelling_a_round_releases_both_registrations() {
        let registry = Arc::new(SearchRegistry::new(HashMap::new()));
        let queries = Arc::new(std::sync::Mutex::new(QueryTokens::new(1, QUERY_TOKEN_TTL)));
        let (tx, _rx) = mpsc::channel(1);
        registry.lock().unwrap().insert([1; 32], tx);
        queries.lock().unwrap().try_insert([1; 32], QueryToken {
            prev: PeerId([0; 32]), key: [0; 64], next: vec![],
        }).unwrap();
        let round = SearchRound { registry: registry.clone(), query_tokens: queries.clone(), tokens: vec![[1; 32]], task: None };
        drop(round);
        assert!(registry.lock().unwrap().is_empty());
        assert!(queries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn search_deadline_and_cancellation_own_all_resources() {
        use crate::transport::tcp::TcpTransport;
        use tokio::net::{TcpListener, TcpStream};
        let local = Keypair::generate_ed25519();
        let remote = Keypair::generate_ed25519();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            PeerLink::responder(Box::new(TcpTransport::new(stream)), &remote).await.unwrap()
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        let link = PeerLink::initiator(Box::new(TcpTransport::new(stream)), &local, None).await.unwrap();
        let _remote_link = server.await.unwrap();
        let node = Node::new(local);
        node.links.lock().await.insert(link.remote_peer(), Arc::new(link));
        let key = DhtId([7; 64]);
        let (held, _) = VerifiedRecord::new_content(b"held", WATCH_REGISTRATION);
        let held_key = held.record().key;
        node.dht_store.lock().await.put(held);
        let mut held_search = tokio::time::timeout(Duration::from_millis(100),
            node.dht_search(held_key, Instant::now() + Duration::from_secs(10)))
            .await.expect("walk launch blocked a held result");
        assert!(held_search.next().await.is_some());
        drop(held_search);
        assert!(node.query_tokens.lock().unwrap().is_empty());
        assert!(node.dht_searches.lock().unwrap().is_empty());
        let mut search = node.dht_search(key, Instant::now() + Duration::from_millis(20)).await;
        let task = search.rounds[0].task.as_ref().unwrap().abort_handle();
        assert!(!node.query_tokens.lock().unwrap().is_empty());
        tokio::task::yield_now().await;
        assert!(tokio::time::timeout(Duration::from_millis(100), search.next()).await.unwrap().is_none());
        assert!(node.query_tokens.lock().unwrap().is_empty(), "deadline retained reverse-path capacity");
        assert!(node.dht_searches.lock().unwrap().is_empty());
        drop(search);
        tokio::task::yield_now().await;
        assert!(task.is_finished(), "cancelled search left its send task alive");
        assert!(node.query_tokens.lock().unwrap().is_empty());
        assert!(node.dht_searches.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn full_application_queue_does_not_block_watch_protocols() {
        let node = Node::new(Keypair::generate_ed25519());
        let kp = Keypair::generate_ed25519();
        let key = DhtId([42; 64]);
        node.local_watches.lock().await.insert(
            *key.as_bytes(),
            LocalWatch::new(Instant::now() + WATCH_REGISTRATION),
        );
        for sequence in 0..257 {
            let record =
                VerifiedRecord::new_signed_at_key(&kp, key, b"news", sequence, WATCH_REGISTRATION);
            tokio::time::timeout(Duration::from_secs(1), node.tell_app(record))
                .await
                .unwrap();
        }
        assert_eq!(
            node.local_watches.lock().await[key.as_bytes()].told[&kp.peer_id()],
            255
        );
        let mut receiver = node.take_dht_watch_receiver().await.unwrap();
        receiver.recv().await.unwrap();
        node.tell_app(VerifiedRecord::new_signed_at_key(
            &kp,
            key,
            b"news",
            256,
            WATCH_REGISTRATION,
        ))
        .await;
        assert_eq!(
            node.local_watches.lock().await[key.as_bytes()].told[&kp.peer_id()],
            256
        );
    }
    #[tokio::test]
    async fn refused_publications_report_failure() {
        let node = Node::new(Keypair::generate_ed25519());
        let mut limits = StorageLimits::default();
        limits.max_records = 0;
        *node.dht_store.lock().await = DhtStore::with_limits(&node.peer_id(), limits);
        assert!(node.dht_put_content(b"no capacity").await.is_err());
        assert_eq!(node.dht_store.lock().await.record_count(), 0);
    }

    #[tokio::test]
    async fn an_offline_search_does_not_consume_a_walk_round() {
        let node = Node::new(Keypair::generate_ed25519());
        let search = node
            .dht_search(DhtId([7; 64]), Instant::now() + Duration::from_secs(10))
            .await;
        assert!(search.rounds.is_empty());
        assert_eq!(search.rounds_left, SEARCH_ROUNDS);
    }

    #[test]
    fn an_offline_watch_does_not_delay_its_first_real_launch() {
        let mut watch = LocalWatch::new(Instant::now() + WATCH_REGISTRATION);
        assert!(!watch.new_round(Vec::new(), WATCH_REGISTRATION));
        assert!(watch.new_round(vec![([1; 32], PeerId([2; 32]))], WATCH_REGISTRATION));
    }
    #[test]
    fn short_watch_extensions_remain_bounded_without_dropping_live_paths() {
        let mut watch = LocalWatch::new(Instant::now() + WATCH_REGISTRATION);
        for round in 0..4 {
            assert!(watch.new_round(
                vec![([round; 32], PeerId([2; 32])); crate::dht::MAX_WALKS],
                Duration::from_secs(1)
            ));
        }
        assert!(!watch.new_round(vec![([9; 32], PeerId([2; 32]))], Duration::from_secs(1)));
        assert!(watch.owns(&[0; 32], &PeerId([2; 32])));
        assert_eq!(watch.tokens.len(), 4 * crate::dht::MAX_WALKS);
    }
}
