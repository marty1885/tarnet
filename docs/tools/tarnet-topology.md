# Tarnet Topology Simulator

`tarnet-topsim` builds a large synthetic tarnet using real tarnet nodes, real link handshakes, and real distance-vector routing. It is a test tool for checking how the network behaves as topologies grow, not a production daemon.

Unlike `tarnetd`, the simulator runs all nodes in one process and uses an in-process transport by default. That avoids file-descriptor limits and lets you exercise topologies with hundreds or thousands of nodes on one machine.

## What It Simulates

The simulator generates a geography-shaped network with:

- IX nodes
- city distributors
- regional distributors
- local distributors
- household gateways
- household devices
- long-haul repeater chains between distant edge-side nodes
- optional local peering and residential shortcuts

It does not simulate bandwidth, packet loss, radio interference, or physical routing protocols. The model is about topology shape and routing convergence.

## Startup Model

The simulator does not bring the whole network up at once. It uses phased rollout, which is closer to how a real network would be built:

1. Core distributors: IX, city, regional, local
2. Gateways: homes come online
3. Edge and repeater nodes: household devices and long-haul relays
4. Deferred links: secondary uplinks, shortcuts, and optional extra links

There is a short pause between phases, then a final settle window before probing.

This matters. Large networks fail badly if every node tries to bootstrap to every upstream at the same instant.

## Topology Shape

The generated graph is intentionally hierarchical:

- homes are star topologies around a gateway
- gateways attach to local distributors
- locals attach to regional distributors
- regionals attach to cities
- cities attach to IX nodes

Optional links are added afterward:

- nearby locals may peer directly
- nearby gateways may form resident shortcuts
- distant edge-side nodes may be joined by repeater chains

Repeater chains are spread with a force-based layout pass so the result does not collapse into a single straight line.

## Running It

```bash
cargo run -p tarnet-topsim -- --nodes 500 --probes 50 --settle-secs 15
```

Useful options:

- `--nodes <N>`: total simulated nodes
- `--seed <N>`: deterministic topology/probe seed
- `--probes <N>`: number of route probes to run
- `--settle-secs <N>`: final convergence wait after all phases
- `--parallel-tests <N>`: max probes in flight, `0` means unlimited
- `--svg <path>`: write an SVG visualization
- `--dot <path>`: write a Graphviz DOT file
- `--list-links`: print per-node direct peer counts
- `--verbose`: increase log output

Example:

```bash
cargo run -p tarnet-topsim -- \
  --nodes 2000 \
  --probes 100 \
  --settle-secs 15 \
  --parallel-tests 32 \
  --svg /tmp/topology.svg
```

## Probe Execution

After the settle window, the simulator picks probe pairs from:

- same household
- same city
- inter-city

It then calls the real `route_probe()` path on live nodes. Probe progress is printed as it runs:

```plaintext
probe 17/50: 140 -> 892 ok cost=7 in 842ms
```

At the end it prints total success rate, average probe cost, average probe latency, and category-by-category success rates.

## Reading The Link Numbers

The simulator prints:

```plaintext
links: expected=269, actual=269, isolated=4, avg_degree=1.99
```

- **expected**: planned topology edges
- **actual**: direct links the live nodes report after startup
- **isolated**: nodes with no direct peers at snapshot time
- **avg_degree**: mean direct neighbors per node

If `actual` is much lower than `expected`, the most common causes are:

- too little settle time
- startup contention during large runs
- optional links being attempted before the base hierarchy stabilises
- measurement timeout pressure on very large runs

## SVG Output

`--svg` writes a dark-theme topology map with the simulation parameters and results embedded at the top.

The colors mean:

- green: planned links that came up
- red dashed: planned links that failed
- gray dashed: unexpected direct links
- blue dashed: successful probes
- red dashed probe overlay: failed probes

Node colors distinguish IX, city, regional, local, gateway, device, and repeater nodes.

## In-Process Transport

The in-process transport is not just a direct function call. It has:

- bounded frame queues
- bounded in-flight buffer credits per direction
- backpressure when credits are exhausted

This is important because otherwise one fast sender could grow memory without bound.

## Choosing `--parallel-tests`

`--parallel-tests` only limits probe concurrency. It does not change how the network is built.

- `0`: unlimited probes in flight
- small value like `8` or `16`: useful when a very large simulation is CPU-bound and probe traffic itself can distort results

If you are testing startup or link-establishment quality, keep probe concurrency modest so the measurement phase does not become the bottleneck.

## What To Tune First

For larger runs:

1. Increase `--settle-secs`
2. Reduce `--parallel-tests`
3. Inspect the SVG before changing the topology generator

If link success drops sharply as node count grows, the problem is usually convergence pressure or startup contention before it is a topology-shape problem.
