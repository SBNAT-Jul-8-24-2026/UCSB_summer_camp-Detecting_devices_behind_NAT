"""Build same-IP / different-IP pair samples from curated flow + header features."""

from __future__ import annotations

import csv
import json
import math
import random
import statistics
from collections import Counter
from itertools import combinations
from pathlib import Path

base_dir = Path(__file__).resolve().parent
header_folder = base_dir / "ip_tcp_headers_summary"
feature_folder = base_dir / "new_flow_features"
json_file_path = base_dir / "flows.json"

# Curated CICFlowMeter / new_flow_features columns (no src_ip / dst_ip).
FLOW_FEATURE_KEYS = [
    "protocol",
    "flow_duration",
    "tot_fwd_pkts",
    "tot_bwd_pkts",
    "flow_byts_s",
    "flow_pkts_s",
    "fwd_pkts_s",
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_max",
    "pkt_len_min",
    # IAT (trimmed)
    "flow_iat_mean",
    "flow_iat_std",
    "fwd_iat_mean",
    "bwd_iat_mean",
    # Directional
    "down_up_ratio",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_max",
    # TCP flag counts from flow summary
    "syn_flag_cnt",
    "ack_flag_cnt",
    "fin_flag_cnt",
    "rst_flag_cnt",
    "psh_flag_cnt",
    "urg_flag_cnt",
    # Initial window bytes
    "init_fwd_win_byts",
    "init_bwd_win_byts",
]

# Aggregated header features (never includes source/dest IP or ports).
HEADER_FEATURE_KEYS = [
    "ip_version",
    "ip_ttl_mean",
    "ip_ttl_std",
    "ip_len_mean",
    "ip_len_std",
    "ip_flag_df_rate",
    "ip_flag_mf_rate",
    "tcp_win_size_mean",
    "tcp_win_size_std",
    "tcp_seq_mean_delta",
    "tcp_ack_mean_delta",
]

FEATURE_KEYS = FLOW_FEATURE_KEYS + HEADER_FEATURE_KEYS

# Identity columns that must never enter the model.
HEADER_DROP_COLUMNS = {
    "IP_Source",
    "IP_Destination",
    "TCP_Source_Port",
    "TCP_Destination_Port",
}


if not json_file_path.exists():
    print(f" 找不到文件：{json_file_path.name}")
    IP_TO_FLOWS_DICT: dict[str, list[str]] = {}
else:
    with open(json_file_path, "r", encoding="utf-8") as f:
        raw_dict = json.load(f)

    IP_TO_FLOWS_DICT = {}
    for ip, flows in raw_dict.items():
        cleaned_flows = []
        for flow in flows:
            cleaned_flows.append(flow.replace(".pcap", ""))
        IP_TO_FLOWS_DICT[ip] = cleaned_flows


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    text = str(value).strip()
    if text == "":
        return None
    lower = text.lower()
    if lower in {"none", "nan"}:
        return None
    if lower == "true":
        return 1.0
    if lower == "false":
        return 0.0
    try:
        return float(text)
    except ValueError:
        return None


def _safe_std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return float(statistics.pstdev(values))


def _mean_abs_delta(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    deltas = [abs(values[i] - values[i - 1]) for i in range(1, len(values))]
    return float(statistics.fmean(deltas))


def _flow_csv_path(flow_name: str) -> Path:
    return feature_folder / f"{flow_name}.csv"


def _header_csv_path(flow_name: str) -> Path:
    return header_folder / f"{flow_name}.pcap_headers.csv"


def get_flow_features(flow_name: str) -> dict[str, float] | None:
    """Read only the curated new_flow_features columns."""
    path = _flow_csv_path(flow_name)
    if not path.exists():
        return None

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            row = next(reader, None)
            if row is None:
                return None

            feats: dict[str, float] = {}
            for key in FLOW_FEATURE_KEYS:
                value = _to_float(row.get(key))
                feats[key] = 0.0 if value is None else round(value, 6)
            return feats
    except (OSError, ValueError, StopIteration):
        return None


def get_header_features(flow_name: str) -> dict[str, float] | None:
    """Aggregate selected IP/TCP header fields.

    Drops source/destination IPs and ports. Uses seq/ack growth (mean abs
    delta) instead of raw sequence numbers. IP version is set to 4 for this
    IPv4 header dataset (no version column in the CSV).
    """
    path = _header_csv_path(flow_name)
    if not path.exists():
        return None

    ttls: list[float] = []
    lengths: list[float] = []
    windows: list[float] = []
    seqs: list[float] = []
    acks: list[float] = []
    df_count = 0
    mf_count = 0
    packet_count = 0

    try:
        with path.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file)
            for row in reader:
                for dropped in HEADER_DROP_COLUMNS:
                    row.pop(dropped, None)

                packet_count += 1

                ttl = _to_float(row.get("IP_TTL"))
                if ttl is not None:
                    ttls.append(ttl)

                length = _to_float(row.get("IP_Length"))
                if length is not None:
                    lengths.append(length)

                window = _to_float(row.get("TCP_Window_Size"))
                if window is not None:
                    windows.append(window)

                seq = _to_float(row.get("TCP_Sequence"))
                if seq is not None:
                    seqs.append(seq)

                ack = _to_float(row.get("TCP_Acknowledgement"))
                if ack is not None:
                    acks.append(ack)

                flags = (row.get("IP_Flags") or "").upper()
                if "DF" in flags:
                    df_count += 1
                if "MF" in flags:
                    mf_count += 1
    except OSError:
        return None

    if packet_count == 0:
        return None

    return {
        "ip_version": 4.0,  # header CSVs are IPv4-only in this project
        "ip_ttl_mean": round(statistics.fmean(ttls), 6) if ttls else 0.0,
        "ip_ttl_std": round(_safe_std(ttls), 6),
        "ip_len_mean": round(statistics.fmean(lengths), 6) if lengths else 0.0,
        "ip_len_std": round(_safe_std(lengths), 6),
        "ip_flag_df_rate": round(df_count / packet_count, 6),
        "ip_flag_mf_rate": round(mf_count / packet_count, 6),
        "tcp_win_size_mean": round(statistics.fmean(windows), 6) if windows else 0.0,
        "tcp_win_size_std": round(_safe_std(windows), 6),
        "tcp_seq_mean_delta": round(_mean_abs_delta(seqs), 6),
        "tcp_ack_mean_delta": round(_mean_abs_delta(acks), 6),
    }


def get_combined_features(flow_name: str) -> dict[str, float] | None:
    """Merge curated flow features + header aggregates for one flow."""
    flow_feats = get_flow_features(flow_name)
    header_feats = get_header_features(flow_name)
    if flow_feats is None or header_feats is None:
        return None
    return {**flow_feats, **header_feats}


def _pair_diff(feats_a: dict[str, float], feats_b: dict[str, float]) -> list[float]:
    diff = [round(abs(feats_a[key] - feats_b[key]), 6) for key in FEATURE_KEYS]
    return [0.0 if not math.isfinite(v) else v for v in diff]


def _filter_ips(min_flows: int, max_flows: int) -> dict[str, list[str]]:
    return {
        ip: flows
        for ip, flows in IP_TO_FLOWS_DICT.items()
        if min_flows <= len(flows) <= max_flows
    }


def _build_feature_cache(
    filtered: dict[str, list[str]],
) -> dict[str, dict[str, float]]:
    cache: dict[str, dict[str, float]] = {}
    for flows in filtered.values():
        for flow_name in flows:
            if flow_name in cache:
                continue
            feats = get_combined_features(flow_name)
            if feats is not None:
                cache[flow_name] = feats
    return cache


def save_dataset_csv(
    rows: list[dict[str, float | int | str]],
    output_csv: Path,
) -> None:
    if not rows:
        raise ValueError("No rows to save.")
    fieldnames = ["flow_a", "flow_b", "ip_a", "ip_b"] + list(FEATURE_KEYS) + ["label"]
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with output_csv.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def prepare_dataset(
    min_flows: int = 3,
    max_flows: int = 8,
    neg_per_flow: int = 2,
    output_csv: str | Path | None = None,
    random_state: int = 42,
):
    """Build exhaustive same-IP pairs + sampled cross-IP pairs.

    - Keep IPs whose flow count is in ``[min_flows, max_flows]``.
    - Positive (label=1): all C(n, 2) pairs inside each IP.
    - Negative (label=0): each flow paired with ``neg_per_flow`` flows
      from other IPs.
    - Feature vector is ``|feat_A - feat_B|`` using the curated flow+header
      columns. All vectors are written to ``output_csv``.

    Returns:
        A_features_list, B_features_list, diff_features_list (X), label_list (y)
    """
    if not IP_TO_FLOWS_DICT:
        return [], [], [], []

    rng = random.Random(random_state)
    filtered = _filter_ips(min_flows, max_flows)
    if not filtered:
        return [], [], [], []

    print(f"Filtered IPs with flows in [{min_flows}, {max_flows}]: {len(filtered)}")
    print("Building feature cache...")
    cache = _build_feature_cache(filtered)

    # Keep only flows that successfully loaded features.
    filtered = {ip: [f for f in flows if f in cache] for ip, flows in filtered.items()}
    filtered = {ip: flows for ip, flows in filtered.items() if len(flows) >= 2}
    if len(filtered) < 2:
        return [], [], [], []

    flow_to_ip = {flow: ip for ip, flows in filtered.items() for flow in flows}

    A_features_list: list[list[float]] = []
    B_features_list: list[list[float]] = []
    diff_features_list: list[list[float]] = []
    label_list: list[int] = []
    csv_rows: list[dict[str, float | int | str]] = []

    def add_pair(flow_a: str, flow_b: str, label: int) -> None:
        feats_a = cache[flow_a]
        feats_b = cache[flow_b]
        diff = _pair_diff(feats_a, feats_b)
        A_features_list.append([feats_a[key] for key in FEATURE_KEYS])
        B_features_list.append([feats_b[key] for key in FEATURE_KEYS])
        diff_features_list.append(diff)
        label_list.append(label)

        row: dict[str, float | int | str] = {
            "flow_a": flow_a,
            "flow_b": flow_b,
            "ip_a": flow_to_ip[flow_a],
            "ip_b": flow_to_ip[flow_b],
            "label": label,
        }
        for key, value in zip(FEATURE_KEYS, diff):
            row[key] = value
        csv_rows.append(row)

    # Positive pairs: C(n, 2) within each IP.
    for ip, flows in filtered.items():
        for flow_a, flow_b in combinations(flows, 2):
            add_pair(flow_a, flow_b, 1)

    pos_count = len(label_list)

    # Negative pairs: each flow x m flows from other IPs.
    for ip, flows in filtered.items():
        other_flows = [
            flow
            for other_ip, other_list in filtered.items()
            if other_ip != ip
            for flow in other_list
        ]
        if not other_flows:
            continue
        sample_n = min(neg_per_flow, len(other_flows))
        for flow_a in flows:
            for flow_b in rng.sample(other_flows, sample_n):
                add_pair(flow_a, flow_b, 0)

    neg_count = len(label_list) - pos_count
    print(f"Positive pairs (label=1): {pos_count}")
    print(f"Negative pairs (label=0): {neg_count}")
    print(f"Total pairs: {len(label_list)}  feature_dim={len(FEATURE_KEYS)}")

    if output_csv is None:
        output_csv = base_dir / "pair_features.csv"
    else:
        output_csv = Path(output_csv)
    save_dataset_csv(csv_rows, output_csv)
    print(f"Saved pair vectors to {output_csv}")

    return A_features_list, B_features_list, diff_features_list, label_list


if __name__ == "__main__":
    A_list, B_list, X, y = prepare_dataset()
    print(f"pairs={len(X)}  feature_dim={len(FEATURE_KEYS)}  same_ip={sum(y)}")
    print("FLOW_FEATURE_KEYS:")
    for key in FLOW_FEATURE_KEYS:
        print(f"  {key}")
    print("HEADER_FEATURE_KEYS:")
    for key in HEADER_FEATURE_KEYS:
        print(f"  {key}")
    if X:
        print("sample X[0][:10] =", X[0][:10])
        print("label balance:", Counter(y))
