# Controlled relay benchmark

The benchmark runs on demand and measures a chosen path to one operator-owned fixture. A wired LAN client runs bounded HTTPS upload or download while sending sequenced UDP echo probes. Run a UDP-only baseline first, then repeat with HTTPS load. Record the router WAN and relay interface counters during each run to verify the path. Use the [relay qualification procedure](../../docs/RELAY-RESILIENCE.md#performance-and-controlled-path-benchmark) for matched comparisons and deployment acceptance.

The client uses Python 3.8 or later and an installed curl 8.4 or later for HTTPS. The fixture uses the Python standard library. Use an existing certificate and TLS listener that forwards the `/flr-benchmark/` paths to the fixture on `127.0.0.1:39081`. Restrict those paths to the measurement source and disable caching and compression for them. The UDP listener binds a specific fixture address and answers only the allowlisted source address as seen by the fixture. Run the fixture on an approved measurement network. The addresses below are placeholders.

On the fixture server, allow startup time before the client deadline and use a byte budget at least as large as the client budget.

```sh
python3 server/relay-benchmark/flr-relay-benchmark.py serve \
  --udp-bind 198.51.100.42 --allow-source 198.51.100.43 \
  --seconds 180 --max-mib 2048
```

On the wired client, use an assigned source address and the exact fixture address for the path under test. The TLS name supplies certificate verification and SNI. The client pins that name to the fixture address for the run.

```sh
python3 server/relay-benchmark/flr-relay-benchmark.py run \
  --source-ip 192.168.8.3 --target-ip 198.51.100.42 \
  --tls-name relay.example.com --direction download --streams 4 \
  --seconds 60 --max-mib 2048
```

Repeat with `--direction upload` and `--direction idle`. Use `--streams 1` to compare single-stream throughput. Choose a budget that sustains the intended load for the test window. `https_budget_reached` and `https_elapsed_seconds` identify runs that used the budget early. The UDP probe runs for the full requested duration. Restart the fixture between matched runs to reset its aggregate limits and counters.

The client reports acknowledged HTTPS payload, goodput, UDP loss, RTT percentiles and the p95 difference between consecutive successful RTTs. Goodput includes the connection and HTTP overhead between completed chunks. UDP loss counts transmitted probes whose expected replies were absent at the deadline. The fixture reports complete payload and aggregate UDP counts. Runs with a failed worker, an incomplete HTTPS stream, or no UDP reply return a nonzero status. Review loss, deadline truncation and throughput against the acceptance thresholds for the deployment.

## Collect router and relay counters

Start the sampler locally on the router and relay around the same wired client
run. Set `wan_device` and `tunnel_device` to the interface names on each host.
Save each host's output with the run receipt.

```sh
sh flr-relay-counters.sh --seconds 60 --interface "$wan_device" \
  --interface "$tunnel_device" > counters.tsv
```

The Linux sampler uses the existing shell and system counters. It reads up to
four interfaces and sleeps for 1–120 seconds between snapshots. Match its UTC
interval to the client receipt's `started_epoch_seconds` and
`finished_epoch_seconds`. The measured interval also includes counter collection.

The TSV reports per-core CPU ticks, interface bytes, packets, errors and drops,
host TCP retransmits, UDP errors, and IPv4 fragmentation counters. It can add
root qdisc counters and backlog snapshots when `tc` and `timeout` are available.
`-` marks an unavailable value or delta, including counters reset between reads.
TCP and UDP counters include other host traffic. Backlog snapshots show the
queue at each end of the run, so a peak during the run can pass between samples.

## Compare matched runs

Save the JSON printed by each `run` command. Repeat control and candidate
measurements against the same controlled destination with the same direction,
duration, stream count, byte budget, UDP rate, and packet size. Compare them in
the order they were collected.

```sh
python3 server/relay-benchmark/flr-relay-benchmark.py compare \
  --pair control-1.json candidate-1.json \
  --pair control-2.json candidate-2.json \
  --pair control-3.json candidate-3.json
```

The output gives each pair's candidate-to-control HTTPS goodput ratio and
changes in UDP loss, p95/p99 RTT, and p95 jitter. It also gives medians and the
number of valid pairs for each metric. Keep failed run receipts with your notes.
The comparison refuses failed runs and mismatched workloads. Check the HTTPS
elapsed time and byte-budget flags before interpreting loaded UDP results.
A transfer that spends its budget early leaves part of the UDP interval unloaded.
