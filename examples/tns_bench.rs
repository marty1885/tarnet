//! Benchmark opaque TNS publication and resolution with a hybrid owner.
//!
//! Run with `cargo run --release -p tarnet --example tns_bench --offline`.
//! Measures local crypto and admission, with no peers, disk, or network latency.

use std::time::Instant;

use tarnet::{
    identity::Keypair,
    node::Node,
    tns::{self, TnsRecord},
};

fn main() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(benchmark());
}

async fn benchmark() {
    let node = Node::new(Keypair::generate_ed25519());
    let owner = Keypair::generate();
    let sid = owner.identity.service_id();
    let values = vec![TnsRecord::Text("benchmark endpoint".into())];
    let mut publishing = Vec::new();
    let mut resolving = Vec::new();
    let mut record_bytes = 0;

    for i in 0..20 {
        // Distinct labels bypass positive answer caching; the immutable zone
        // public key remains cached after the first resolution.
        let label = format!("benchmark-{i}");
        let started = Instant::now();
        tns::publish(&node, &owner, &label, &values).await.unwrap();
        publishing.push(started.elapsed().as_secs_f64() * 1e3);

        let started = Instant::now();
        assert_eq!(tns::lookup_label(&node, &sid, &label).await, values);
        resolving.push(started.elapsed().as_secs_f64() * 1e3);

        if i == 0 {
            let mut keys =
                tns::label_lookup_keys(&owner.identity.signing.signing_pubkey_bytes(), &label)
                    .unwrap();
            keys.push(tarnet::dht::zone_key(&sid));
            for key in keys {
                for record in node.dht_held(&key).await {
                    record_bytes += record.to_put_msg().record_bytes().len();
                }
            }
        }
    }

    publishing.sort_by(f64::total_cmp);
    resolving.sort_by(f64::total_cmp);
    println!("Opaque TNS: hybrid owner, four lanes plus descriptor, 20 short labels.");
    println!("Local crypto and admission only; no peers, disk, or network latency.");
    println!("operation,median_ms,max_ms");
    println!("publish,{:.3},{:.3}", publishing[10], publishing[19]);
    println!("resolve,{:.3},{:.3}", resolving[10], resolving[19]);
    println!("first_label_unreplicated_record_bytes={record_bytes}");
}
