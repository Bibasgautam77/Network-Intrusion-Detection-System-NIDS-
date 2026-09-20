# NIDS — Network Intrusion Detection System

A staged, self-contained NIDS for **authorized lab traffic**: live packet
capture, flow reconstruction, signature-based detection, ML anomaly
detection, an alert engine, a FastAPI backend, and a console-style
dashboard.

> ⚠️ Only run the live sensor against interfaces/networks you own or are
> explicitly authorized to monitor (a home lab, VMs, or a test range).

## Architecture

```
Network Traffic → Sensor (Scapy) → Flow Tracker → Feature Extraction
                                                        │
                                    ┌───────────────────┼───────────────────┐
                                    ▼                                       ▼
                          Signature Engine (YAML rules)          ML Anomaly Detector
                                    │                                       │
                                    └───────────────────┬───────────────────┘
                                                         ▼
                                                  Alert Engine (dedup,
                                                  severity, persistence)
                                                         │
                                                         ▼
                                          SQLite/Postgres  →  FastAPI  →  Dashboard
```

## Project layout

```
nids/
  sensor/capture.py       Live Scapy capture + in-memory flow tracking
  features/extractor.py   Raw flow -> numeric feature vector
  detection/signatures.py Rule-based detection engine (YAML-driven)
  detection/anomaly.py    IsolationForest-based anomaly detector
  alerting/engine.py      Severity scoring, dedup, persistence
  storage/db.py           SQLAlchemy models (Flow, Alert, PacketSample)
  api/main.py             FastAPI backend for the dashboard
  dashboard/index.html    Self-contained web dashboard (no build step)
  pcap/analyzer.py        Offline PCAP investigation using the same engines
  rules/default_rules.yaml  Editable signature rule set
  pipeline.py             Orchestrator: wires sensor -> detection -> alerts
  tests/simulate_traffic.py  Synthetic traffic generator (no live capture needed)
  requirements.txt
```

## Setup

```bash
python3 -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Live capture with Scapy needs elevated privileges on most systems
(`sudo` on Linux/macOS, run-as-Administrator on Windows), and on Linux you
may need `libpcap`: `sudo apt install libpcap-dev tcpdump`.

## Recommended order to bring it up

### 1. See it work end-to-end with synthetic traffic (no root, no NIC needed)

```bash
python -m tests.simulate_traffic
```

This trains a quick anomaly baseline on synthetic "normal" traffic, then
replays a mix of normal and attack-shaped flows (SYN flood, port scan,
large exfil-like transfer, RST flood) through the signature engine, the
anomaly detector, and the alert engine, writing everything to `nids.db`.

### 2. Start the API and open the dashboard

```bash
uvicorn api.main:app --reload --port 8000
```

Then open `dashboard/index.html` directly in a browser (it talks to
`http://localhost:8000` by default — override with
`window.NIDS_API_BASE = "http://your-host:8000"` before the script tag
loads, or edit the `API_BASE` constant, if hosting elsewhere).

You should see the synthetic alerts from step 1 in the console.

### 3. Run against real lab traffic

```bash
sudo python pipeline.py --iface eth0
```

Use `ip link` / `ipconfig` to find your interface name. `--filter` accepts
any BPF expression (default `"ip"`). Alerts stream into the same database
the dashboard reads from.

### 4. Train a real anomaly baseline (recommended before trusting anomaly alerts)

The synthetic baseline from step 1 is just for demoing the pipeline. For
real use:

1. Capture a period of known-clean lab traffic to a pcap:
   `sudo tcpdump -i eth0 -w baseline.pcap -G 600 -W 1`
2. Extract features from it:
   `python -m pcap.analyzer baseline.pcap --export-features baseline.csv`
3. Train the model from that CSV:
   `python -m detection.anomaly baseline.csv --contamination 0.02`

This overwrites `models/anomaly_model.joblib`, which `pipeline.py` and
`pcap/analyzer.py` load automatically.

### 5. Investigate a capture after the fact

```bash
python -m pcap.analyzer suspicious_capture.pcap
```

Runs the same signature + anomaly detection against an offline `.pcap`
file and prints findings — handy for Wireshark-adjacent investigation
without re-running live capture.

## Tuning detection

- **Signatures**: edit `rules/default_rules.yaml`. Each rule is a list of
  field/operator/value conditions evaluated against flow features (see
  `features/extractor.FEATURE_NAMES` for available fields) or raw packet
  fields. `scope: aggregate` rules track behavior across many flows from
  one source (e.g. port scanning).
- **Anomaly sensitivity**: the `contamination` parameter in
  `AnomalyDetector` controls how much of the baseline is expected to be
  "abnormal" — lower it (e.g. 0.01) for a quieter model, raise it for more
  sensitivity.
- **Alert dedup window**: `DEDUP_WINDOW_SECONDS` in `alerting/engine.py`
  controls how long a repeated signature/source/destination combo is
  suppressed before re-alerting.

## Switching storage backends

Default is SQLite (`nids.db`, zero config). To use PostgreSQL, set:

```bash
export NIDS_DB_URL="postgresql+psycopg2://user:pass@localhost:5432/nids"
pip install psycopg2-binary
```

Elasticsearch is listed as optional in `requirements.txt` for teams that
want to move traffic analytics into an ELK-style stack — it isn't wired
into `storage/db.py` by default, since SQL covers the alert/flow schema
well; treat it as a drop-in replacement for the analytics/search layer if
you outgrow SQLite/Postgres for querying at scale.

## Extending

- Add Suricata/Zeek as an alternate sensor: have them emit EVE JSON /
  Zeek logs, write a small adapter that maps their fields into the same
  flow-snapshot shape `sensor/capture.py` produces, and feed it into
  `alerting/engine.py` + `features/extractor.py` unchanged.
- Swap `IsolationForest` for another sklearn model in
  `detection/anomaly.py` — the rest of the pipeline doesn't need to change
  since it only calls `.fit()` / `.score()`.
- The dashboard is a single static HTML file with no build step; extend it
  directly, or point a separate React app at the same FastAPI endpoints
  listed in `api/main.py`.

## Note on this build environment

This project was scaffolded and syntax-checked (`python -m py_compile`)
across every file, and the dependency-light modules (feature extraction,
signature engine) were functionally tested against synthetic attack and
benign traffic. The sandbox used to build this had no network access, so
scapy/FastAPI/SQLAlchemy/scikit-learn could not be installed to run a full
end-to-end live test here — run `pip install -r requirements.txt` and
`python -m tests.simulate_traffic` on your machine as the first sanity
check.
