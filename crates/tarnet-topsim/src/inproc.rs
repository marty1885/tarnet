use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{mpsc, Mutex, Semaphore};

use tarnet::transport::{Discovery, Transport};
use tarnet::types::{Error, Result};

const INPROC_QUEUE_DEPTH: usize = 512;
const INPROC_MTU: usize = 65_535;
const INPROC_BUFFER_BYTES: usize = 4 * 1024 * 1024;
const INPROC_BUFFER_UNIT: usize = 1024;

struct InProcFrame {
    data: Vec<u8>,
    units: u32,
}

pub struct InProcTransport {
    tx: mpsc::Sender<InProcFrame>,
    tx_budget: Arc<Semaphore>,
    rx: Mutex<mpsc::Receiver<InProcFrame>>,
    rx_budget: Arc<Semaphore>,
}

impl InProcTransport {
    fn pair() -> (Self, Self) {
        let (left_tx, left_rx) = mpsc::channel(INPROC_QUEUE_DEPTH);
        let (right_tx, right_rx) = mpsc::channel(INPROC_QUEUE_DEPTH);
        let budget_units = (INPROC_BUFFER_BYTES / INPROC_BUFFER_UNIT) as u32;
        let left_budget = Arc::new(Semaphore::new(budget_units as usize));
        let right_budget = Arc::new(Semaphore::new(budget_units as usize));
        (
            Self {
                tx: left_tx,
                tx_budget: right_budget.clone(),
                rx: Mutex::new(right_rx),
                rx_budget: left_budget.clone(),
            },
            Self {
                tx: right_tx,
                tx_budget: left_budget,
                rx: Mutex::new(left_rx),
                rx_budget: right_budget,
            },
        )
    }
}

#[async_trait]
impl Transport for InProcTransport {
    async fn send(&self, data: &[u8]) -> Result<()> {
        if data.len() > INPROC_MTU {
            return Err(Error::Wire(format!(
                "inproc message {} bytes exceeds mtu {}",
                data.len(),
                INPROC_MTU
            )));
        }
        let units = buffer_units(data.len());
        let permit = self
            .tx_budget
            .clone()
            .acquire_many_owned(units)
            .await
            .map_err(|_| Error::Wire("inproc budget closed".into()))?;
        self.tx
            .send(InProcFrame {
                data: data.to_vec(),
                units,
            })
            .await
            .map_err(|_| Error::Wire("inproc peer closed".into()))?;
        permit.forget();
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut rx = self.rx.lock().await;
        let frame = rx
            .recv()
            .await
            .ok_or_else(|| Error::Wire("inproc peer closed".into()))?;
        if frame.data.len() > buf.len() {
            return Err(Error::Wire(format!(
                "inproc frame {} bytes exceeds buffer {}",
                frame.data.len(),
                buf.len()
            )));
        }
        buf[..frame.data.len()].copy_from_slice(&frame.data);
        self.rx_budget.add_permits(frame.units as usize);
        Ok(frame.data.len())
    }

    fn mtu(&self) -> usize {
        INPROC_MTU
    }

    fn is_reliable(&self) -> bool {
        true
    }

    fn name(&self) -> &'static str {
        "inproc"
    }
}

fn buffer_units(len: usize) -> u32 {
    len.div_ceil(INPROC_BUFFER_UNIT).max(1) as u32
}

#[derive(Clone, Default)]
pub struct InProcNetwork {
    listeners: Arc<Mutex<HashMap<String, mpsc::Sender<Box<dyn Transport>>>>>,
}

impl InProcNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        let sender = {
            let listeners = self.listeners.lock().await;
            listeners
                .get(addr)
                .cloned()
                .ok_or_else(|| Error::Wire(format!("unknown inproc address {}", addr)))?
        };

        let (local, remote) = InProcTransport::pair();
        sender
            .send(Box::new(remote))
            .await
            .map_err(|_| Error::Wire(format!("inproc listener {} unavailable", addr)))?;
        Ok(Box::new(local))
    }

    pub async fn bind(&self, addr: String) -> Result<InProcDiscovery> {
        let (tx, rx) = mpsc::channel(INPROC_QUEUE_DEPTH);
        let mut listeners = self.listeners.lock().await;
        if listeners.contains_key(&addr) {
            return Err(Error::Wire(format!("duplicate inproc address {}", addr)));
        }
        listeners.insert(addr.clone(), tx);
        drop(listeners);

        Ok(InProcDiscovery {
            network: self.clone(),
            local_addr: addr,
            accept_rx: Mutex::new(rx),
        })
    }
}

pub struct InProcDiscovery {
    network: InProcNetwork,
    local_addr: String,
    accept_rx: Mutex<mpsc::Receiver<Box<dyn Transport>>>,
}

impl InProcDiscovery {
    pub fn local_addr(&self) -> &str {
        &self.local_addr
    }
}

#[async_trait]
impl Discovery for InProcDiscovery {
    async fn accept(&self) -> Result<Box<dyn Transport>> {
        let mut rx = self.accept_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::Wire(format!("inproc listener {} closed", self.local_addr)))
    }

    async fn connect(&self, addr: &str) -> Result<Box<dyn Transport>> {
        self.network.connect(addr).await
    }
}
