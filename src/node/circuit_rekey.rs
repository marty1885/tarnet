//! End-to-end rekey of a circuit's innermost layer (`docs/spec/identity.md`,
//! "Key lifetime"): once an hour the circuit's initiator runs one fresh KEM
//! with the far end, inside the current innermost layer.
//!
//! The initiator switches to the new keys when the answer arrives. The
//! responder stages them and switches its sending side when the first cell
//! under them arrives, so neither end ever seals under keys the other can't
//! open yet. Both keep their old receive keys a while for cells in flight.

use super::*;
use crate::circuit::LayerRekeyMsg;

/// Tries of one rekey before waiting for the next sweep. The same
/// generation and KEM key are retried then, so the ends never diverge.
const REKEY_ATTEMPTS: usize = 5;

impl Node {
    /// Start an end-to-end rekey on every circuit we initiated whose
    /// innermost keys are an hour old.
    pub(super) async fn rekey_circuits(self: &Arc<Self>) {
        let due: Vec<u32> = {
            let mut circuits = self.circuits.outbound.lock().await;
            circuits
                .iter_mut()
                .filter(|(_, c)| {
                    c.state == CircuitPhase::Ready
                        && c.rekey.due(c.created_at, crate::link::REKEY_MAX_AGE)
                })
                .map(|(id, c)| {
                    c.rekey.busy = true;
                    *id
                })
                .collect()
        };
        for circuit_id in due {
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.rekey_circuit(circuit_id).await {
                    log::debug!("Circuit {} rekey failed: {}", circuit_id, e);
                }
            });
        }
    }

    /// Rekey one circuit's innermost layer now (also used by tests). Marks
    /// the circuit busy for the duration.
    pub async fn rekey_circuit_now(self: &Arc<Self>, circuit_id: u32) -> Result<()> {
        {
            let mut circuits = self.circuits.outbound.lock().await;
            let circuit = circuits
                .get_mut(&circuit_id)
                .ok_or_else(|| Error::Protocol("no such circuit".into()))?;
            if circuit.rekey.responder || circuit.rekey.busy {
                return Err(Error::Protocol("circuit can't rekey now".into()));
            }
            circuit.rekey.busy = true;
        }
        self.rekey_circuit(circuit_id).await
    }

    /// Rekey every circuit we initiate now, whatever its age (tests and
    /// operators). Returns how many were rekeyed.
    pub async fn rekey_circuits_now(self: &Arc<Self>) -> Result<usize> {
        let ids: Vec<u32> = {
            let circuits = self.circuits.outbound.lock().await;
            circuits
                .iter()
                .filter(|(_, c)| c.state == CircuitPhase::Ready && !c.rekey.responder)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in &ids {
            self.rekey_circuit_now(*id).await?;
        }
        Ok(ids.len())
    }

    /// Run one rekey on a circuit already marked busy.
    async fn rekey_circuit(&self, circuit_id: u32) -> Result<()> {
        let result = self.run_layer_rekey(circuit_id).await;
        if let Some(c) = self.circuits.outbound.lock().await.get_mut(&circuit_id) {
            c.rekey.busy = false;
        }
        self.circuits.pending_layer_rekeys.lock().await.remove(&circuit_id);
        result
    }

    async fn run_layer_rekey(&self, circuit_id: u32) -> Result<()> {
        for _ in 0..REKEY_ATTEMPTS {
            let (tx, rx) = oneshot::channel();
            self.circuits.pending_layer_rekeys.lock().await.insert(circuit_id, tx);
            let (first_hop, cid, cells, layers) = {
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = circuits
                    .get_mut(&circuit_id)
                    .ok_or_else(|| Error::Protocol("circuit gone".into()))?;
                let request = circuit.rekey.request();
                let (first_hop, cid, cells) = circuit.send_relay_message(&RelayCell {
                    command: RelayCellCommand::LayerRekey,
                    stream_id: 0,
                    data: request.to_bytes(),
                })?;
                (first_hop, cid, cells, circuit.layers.len())
            };
            let bytes = cells.len() * CELL_SIZE;
            for cell in &cells {
                self.send_to_peer_critical(&first_hop, &encode_circuit_relay_cell(cid, cell))
                    .await?;
            }
            // The answer is about as large as the request.
            let wait = self.extend_step_timeout(first_hop, layers, 2 * bytes).await;
            let Ok(Ok(answer)) = tokio::time::timeout(wait, rx).await else {
                continue;
            };
            let Ok(answer) = LayerRekeyMsg::from_bytes(&answer) else {
                continue;
            };
            {
                let mut circuits = self.circuits.outbound.lock().await;
                let circuit = circuits
                    .get_mut(&circuit_id)
                    .ok_or_else(|| Error::Protocol("circuit gone".into()))?;
                if circuit.layers.len() != layers {
                    // The circuit grew a layer (a rendezvous joined) while we
                    // waited: the answer is for a layer no longer innermost.
                    circuit.rekey.offer = None;
                    return Err(Error::Protocol("innermost layer changed during rekey".into()));
                }
                let chain = circuit
                    .rekey_chain()
                    .ok_or_else(|| Error::Protocol("circuit has no handshake to chain from".into()))?;
                // A late copy of an earlier generation's answer: try again.
                let Ok(keys) = circuit.rekey.complete(chain, &answer) else {
                    continue;
                };
                circuit.layers.rekey_last(keys);
            }
            // A first cell under the new keys switches the far end's sending
            // side; later traffic does too if this one is lost.
            self.send_circuit_data_cmd(circuit_id, RelayCellCommand::Padding, &[])
                .await?;
            log::debug!("Circuit {} innermost layer rekeyed", circuit_id);
            return Ok(());
        }
        Err(Error::Protocol("no answer to circuit rekey".into()))
    }

    /// At a circuit's endpoint: answer the initiator's rekey and stage the
    /// new keys.
    pub(super) async fn handle_layer_rekey_at_endpoint(
        &self,
        from: PeerId,
        circuit_id: u32,
        data: &[u8],
    ) -> Result<()> {
        let msg = LayerRekeyMsg::from_bytes(data)?;
        let (answer, staged) = {
            let mut map = self.circuits.hop_backward_keys.lock().await;
            let hop = map
                .get_mut(&(circuit_id, from))
                .ok_or_else(|| Error::Protocol("rekey for unknown circuit".into()))?;
            let (answer, staged) = hop.rekey.respond(hop.transcript, &msg)?;
            if let Some(keys) = &staged {
                hop.pending = Some(keys.backward.clone());
            }
            (answer, staged)
        };
        if let Some(keys) = staged {
            let key = CircuitKey {
                circuit_id,
                from_peer: from,
            };
            let mut table = self.circuits.table.lock().await;
            let Some(CircuitAction::Endpoint {
                crypto: Some(hop), ..
            }) = table.lookup_mut(&key)
            else {
                return Ok(());
            };
            hop.stage(keys.forward.clone());
        }
        self.send_endpoint_relay_cell(from, circuit_id, RelayCellCommand::LayerRekeyed, &answer)
            .await
    }

    /// The initiator's first cell under staged keys arrived: seal under them
    /// from now on.
    pub(super) async fn adopt_rekeyed_backward(&self, circuit_id: u32, from: PeerId) {
        let mut map = self.circuits.hop_backward_keys.lock().await;
        if let Some(hop) = map.get_mut(&(circuit_id, from)) {
            if let Some(keys) = hop.pending.take() {
                hop.keys = keys;
                hop.counter = 0;
            }
        }
    }

    /// On a circuit we built whose innermost layer the other end rekeys (the
    /// service side of a rendezvous): answer and stage the new keys.
    pub(super) async fn handle_layer_rekey_on_circuit(&self, circuit_id: u32, data: &[u8]) -> Result<()> {
        let msg = LayerRekeyMsg::from_bytes(data)?;
        let (first_hop, cid, cells) = {
            let mut circuits = self.circuits.outbound.lock().await;
            let Some(circuit) = circuits.get_mut(&circuit_id) else {
                return Ok(());
            };
            if !circuit.rekey.responder {
                return Err(Error::Protocol("rekey on a circuit we initiate".into()));
            }
            let chain = circuit
                .rekey_chain()
                .ok_or_else(|| Error::Protocol("circuit has no handshake to chain from".into()))?;
            let (answer, staged) = circuit.rekey.respond(chain, &msg)?;
            if let Some(keys) = staged {
                circuit.layers.stage_last(keys.responder());
            }
            circuit.send_relay_message(&RelayCell {
                command: RelayCellCommand::LayerRekeyed,
                stream_id: 0,
                data: answer,
            })?
        };
        for cell in &cells {
            self.send_to_peer_critical(&first_hop, &encode_circuit_relay_cell(cid, cell))
                .await?;
        }
        Ok(())
    }
}
