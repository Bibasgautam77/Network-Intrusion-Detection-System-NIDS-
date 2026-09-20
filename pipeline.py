"""
Main orchestrator: starts the sensor, drains its flow/packet queues, runs
signature + anomaly detection, and writes alerts to storage.

Run:
    sudo python pipeline.py --iface eth0
    sudo python pipeline.py --iface eth0 --no-anomaly   (signatures only)

Requires: an authorized interface/lab network. Live capture needs elevated
privileges on most systems.
"""
import argparse
import queue
import threading
import time
from pathlib import Path

from sensor.capture import run_sensor
from features.extractor import extract_features, feature_vector
from detection.signatures import SignatureEngine
from detection.anomaly import AnomalyDetector, DEFAULT_MODEL_PATH
from alerting.engine import AlertEngine, persist_flow
from storage.db import init_db


def flow_consumer(flow_queue: "queue.Queue", sig_engine: SignatureEngine,
                   anomaly_detector: AnomalyDetector, alert_engine: AlertEngine,
                   stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            flow_meta = flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        features = extract_features(flow_meta)
        flow_id = persist_flow(flow_meta, features)

        # --- Signature-based detection ---
        sig_hits = sig_engine.evaluate_flow(features, flow_meta)
        for hit in sig_hits:
            alert_id = alert_engine.raise_signature_alert(hit, flow_id=flow_id)
            if alert_id:
                print(f"[ALERT][signature:{hit['signature_id']}] "
                      f"{flow_meta['src_ip']} -> {flow_meta['dst_ip']} "
                      f"({hit['severity']}) {hit['signature_name']}")

        # Aggregate (cross-flow) signature checks, e.g. port-scan detection
        agg_hits = sig_engine.evaluate_aggregate(flow_meta["src_ip"], flow_meta.get("dst_port"))
        for hit in agg_hits:
            alert_id = alert_engine.raise_signature_alert(hit, flow_id=flow_id)
            if alert_id:
                print(f"[ALERT][signature:{hit['signature_id']}] "
                      f"{flow_meta['src_ip']} scanning behaviour ({hit['severity']})")

        # --- ML anomaly detection ---
        if anomaly_detector and anomaly_detector.is_fitted:
            vector = feature_vector(flow_meta)
            result = anomaly_detector.score(vector)
            if result["is_anomaly"]:
                alert_id = alert_engine.raise_anomaly_alert(flow_meta, result, flow_id=flow_id)
                if alert_id:
                    print(f"[ALERT][anomaly] {flow_meta['src_ip']} -> {flow_meta['dst_ip']} "
                          f"score={result['anomaly_score']:.2f}")


def packet_consumer(packet_queue: "queue.Queue", sig_engine: SignatureEngine,
                     alert_engine: AlertEngine, stop_event: threading.Event):
    while not stop_event.is_set():
        try:
            pkt_event = packet_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        hits = sig_engine.evaluate_packet(pkt_event)
        for hit in hits:
            alert_engine.raise_signature_alert(hit)


def main():
    parser = argparse.ArgumentParser(description="NIDS pipeline: sensor -> detection -> alerts")
    parser.add_argument("--iface", default=None, help="Interface to sniff")
    parser.add_argument("--filter", default="ip", help="BPF filter")
    parser.add_argument("--no-anomaly", action="store_true", help="Disable ML anomaly detection")
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH), help="Path to trained anomaly model")
    args = parser.parse_args()

    init_db()

    flow_q, packet_q = queue.Queue(), queue.Queue()
    stop_event = threading.Event()

    sig_engine = SignatureEngine()
    alert_engine = AlertEngine()

    anomaly_detector = None
    if not args.no_anomaly:
        model_path = Path(args.model)
        if model_path.exists():
            anomaly_detector = AnomalyDetector.load(model_path)
            print(f"[pipeline] Loaded anomaly model from {model_path}")
        else:
            print(f"[pipeline] No anomaly model found at {model_path}. "
                  f"Run detection/anomaly.py to train one. Continuing with signatures only.")

    threads = [
        threading.Thread(target=flow_consumer, args=(flow_q, sig_engine, anomaly_detector, alert_engine, stop_event), daemon=True),
        threading.Thread(target=packet_consumer, args=(packet_q, sig_engine, alert_engine, stop_event), daemon=True),
    ]
    for t in threads:
        t.start()

    try:
        run_sensor(args.iface, flow_q, packet_q, bpf_filter=args.filter, stop_event=stop_event)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[pipeline] Shutting down...")
        stop_event.set()
        time.sleep(1)


if __name__ == "__main__":
    main()
