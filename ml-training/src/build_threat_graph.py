"""
build_threat_graph.py — Milestone 14 (optional)

Builds a threat intelligence graph from a batch of analyzed samples,
using the models already trained in M3/M4/M5/M6. Per the blueprint's own
Section 24, this starts with NetworkX (not a graph database or GNN --
those need a real justification this project doesn't have yet).

Nodes:
  - Sample nodes: one per analyzed row (classification, threat level,
    anomaly score as attributes)
  - Family nodes: one per distinct predicted malware family

Edges:
  - Sample -> Family ("belongs_to"): for malicious samples with a
    family prediction
  - Sample -> Sample ("shares_characteristics_with"): between two
    samples whose top-5 SHAP-contributing features overlap by at least
    a Jaccard similarity threshold -- an operationalization of "shares
    characteristics with" grounded in the explainability work already
    done in M6, not an invented relationship

This is explicitly the OPTIONAL, advanced phase per the blueprint --
scoped to NetworkX + basic community detection, not graph embeddings or
GNNs, since nothing here justifies that additional complexity yet.

Usage (from the ThreatLens/ directory, with the venv active):

    python ml-training\\src\\build_threat_graph.py --data-dir ml-training\\data --n-samples 200
"""

import argparse
import sys
from pathlib import Path

import numpy as np


def load_batch(data_dir: str, subset: str, n: int):
    import thrember
    X, y = thrember.read_vectorized_features(data_dir, subset=subset)
    n = min(n, X.shape[0])
    # A fixed random subsample (not just the first n rows) for a more
    # representative graph than whatever happens to be first in the file.
    rng = np.random.default_rng(42)
    idx = rng.choice(X.shape[0], size=n, replace=False)
    return X[idx], y[idx]


def build_feature_names() -> list:
    import thrember
    ext = thrember.PEFeatureExtractor()
    names = []
    for block in ext.features:
        block_name = type(block).__name__
        for i in range(block.dim):
            names.append(f"{block_name}[{i}]")
    return names


def score_batch(detector, anomaly_model, family_model, family_le, thresholds,
                 X, feature_names, top_k=5):
    """Runs the full M3-M6 pipeline on a batch, returning one record per
    sample with everything the graph needs. Reuses risk_engine.py's own
    tier logic for consistency with M7/M8, rather than re-deriving it."""
    import shap
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from risk_engine import base_tier, escalate

    proba = detector.predict_proba(X)[:, 1]
    anomaly_score = -anomaly_model.score_samples(X)

    explainer = shap.TreeExplainer(detector)
    shap_values = explainer.shap_values(X)

    records = []
    for i in range(X.shape[0]):
        tier = base_tier(float(proba[i]), thresholds)
        if anomaly_score[i] >= thresholds["anomaly_cutoff"] and tier != "CRITICAL":
            tier = escalate(tier)

        row_shap = shap_values[i]
        top_idx = np.argsort(-np.abs(row_shap))[:top_k]
        top_features = frozenset(feature_names[j] for j in top_idx)

        family = None
        classification = "MALICIOUS" if proba[i] >= thresholds["thr_f1_optimal"] else "BENIGN"
        if family_model is not None and classification == "MALICIOUS":
            fam_idx = family_model.predict(X[i:i + 1])[0]
            family = str(family_le.inverse_transform([fam_idx])[0])

        records.append({
            "id": f"sample_{i}",
            "classification": classification,
            "threat_level": tier,
            "malicious_probability": round(float(proba[i]), 4),
            "predicted_family": family,
            "top_features": top_features,
        })
    return records


def jaccard(a: frozenset, b: frozenset) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def build_graph(records: list, similarity_threshold: float = 0.4):
    import networkx as nx

    G = nx.Graph()

    for r in records:
        G.add_node(
            r["id"], kind="sample",
            classification=r["classification"], threat_level=r["threat_level"],
            malicious_probability=r["malicious_probability"],
        )
        if r["predicted_family"]:
            fam_node = f"family::{r['predicted_family']}"
            if fam_node not in G:
                G.add_node(fam_node, kind="family", name=r["predicted_family"])
            G.add_edge(r["id"], fam_node, relation="belongs_to")

    for i in range(len(records)):
        for j in range(i + 1, len(records)):
            sim = jaccard(records[i]["top_features"], records[j]["top_features"])
            if sim >= similarity_threshold:
                G.add_edge(records[i]["id"], records[j]["id"],
                           relation="shares_characteristics_with", weight=round(sim, 3))

    return G


def compute_stats(G) -> dict:
    import networkx as nx
    from networkx.algorithms.community import greedy_modularity_communities

    sample_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "sample"]
    family_nodes = [n for n, d in G.nodes(data=True) if d.get("kind") == "family"]

    components = list(nx.connected_components(G))
    largest_component = max(components, key=len) if components else set()

    try:
        communities = list(greedy_modularity_communities(G))
    except Exception:
        communities = []

    return {
        "sample_nodes": len(sample_nodes),
        "family_nodes": len(family_nodes),
        "total_edges": G.number_of_edges(),
        "connected_components": len(components),
        "largest_component_size": len(largest_component),
        "communities_detected": len(communities),
        "largest_community_size": max((len(c) for c in communities), default=0),
    }


def save_visualization(G, out_path: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    TIER_COLORS = {
        "LOW": "#10B981", "MODERATE": "#EAB308", "ELEVATED": "#F97316",
        "HIGH": "#EF4444", "CRITICAL": "#991B1B",
    }
    node_colors = []
    for n, d in G.nodes(data=True):
        if d.get("kind") == "family":
            node_colors.append("#2F6FED")
        else:
            node_colors.append(TIER_COLORS.get(d.get("threat_level"), "#94A3B8"))

    node_sizes = [140 if d.get("kind") == "family" else 40 for _, d in G.nodes(data=True)]

    plt.figure(figsize=(12, 12))
    pos = nx.spring_layout(G, seed=42, k=0.3)
    nx.draw_networkx_edges(G, pos, alpha=0.15, width=0.5)
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.85)
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def write_report(out_path: Path, stats: dict, n_samples: int, similarity_threshold: float) -> None:
    lines = ["# M14 Threat Intelligence Graph Report\n"]
    lines.append(
        f"Built from {n_samples} randomly-sampled test-set rows, scored through "
        f"the M3-M6 pipeline. Sample-to-sample edges require top-5 SHAP feature "
        f"overlap (Jaccard) >= {similarity_threshold}.\n"
    )
    lines.append("## Graph statistics\n")
    for key, val in stats.items():
        lines.append(f"- {key}: {val}")
    lines.append("")
    lines.append(
        "Community detection uses greedy modularity maximization (networkx's "
        "built-in implementation) -- no graph embeddings or GNN, per the "
        "blueprint's guidance to only add that complexity with real "
        "justification, which a first pass at this scale doesn't yet have.\n"
    )
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="M14: build the optional threat intelligence graph.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--subset", default="test_dedup")
    parser.add_argument("--n-samples", type=int, default=200)
    parser.add_argument("--similarity-threshold", type=float, default=0.6)
    parser.add_argument("--models-dir", default="ml-training/models")
    parser.add_argument("--reports-dir", default="ml-training/reports")
    args = parser.parse_args()

    try:
        import joblib
        import json
    except ImportError as e:
        print(f"ERROR: missing dependency ({e}).", file=sys.stderr)
        return 1

    models_dir = Path(args.models_dir)
    for required in ["malware_detector.joblib", "anomaly_detector.joblib", "risk_thresholds.json"]:
        if not (models_dir / required).exists():
            print(f"ERROR: '{models_dir / required}' not found. Run M3/M4/M7 first.", file=sys.stderr)
            return 1

    print("Loading models ...")
    detector = joblib.load(models_dir / "malware_detector.joblib")
    anomaly_model = joblib.load(models_dir / "anomaly_detector.joblib")
    thresholds = json.loads((models_dir / "risk_thresholds.json").read_text(encoding="utf-8"))

    family_model, family_le = None, None
    if (models_dir / "family_classifier.joblib").exists():
        family_model = joblib.load(models_dir / "family_classifier.joblib")
        family_le = joblib.load(models_dir / "family_label_encoder.joblib")

    print(f"Loading {args.n_samples} sample(s) from '{args.subset}' ...")
    X, y = load_batch(args.data_dir, args.subset, args.n_samples)
    feature_names = build_feature_names()

    print("Scoring batch (detection + anomaly + family + SHAP) ...")
    records = score_batch(detector, anomaly_model, family_model, family_le, thresholds, X, feature_names)

    print(f"Building graph (similarity threshold={args.similarity_threshold}) ...")
    G = build_graph(records, similarity_threshold=args.similarity_threshold)

    stats = compute_stats(G)
    print("\n--- Graph statistics ---")
    for key, val in stats.items():
        print(f"{key}: {val}")

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)

    import networkx as nx
    graphml_path = reports_dir / "m14_threat_graph.graphml"
    nx.write_graphml(G, graphml_path)
    print(f"\nGraph saved to: {graphml_path}")

    # JSON export (node-link format) for the frontend's interactive graph view.
    graph_json = nx.node_link_data(G, edges="links")
    json_path = reports_dir / "m14_threat_graph.json"
    json_path.write_text(json.dumps(graph_json), encoding="utf-8")
    print(f"Graph JSON (for the dashboard) saved to: {json_path}")

    viz_path = reports_dir / "m14_threat_graph.png"
    save_visualization(G, viz_path)
    print(f"Visualization saved to: {viz_path}")

    report_path = reports_dir / "m14_threat_graph_report.md"
    write_report(report_path, stats, X.shape[0], args.similarity_threshold)
    print(f"Report written to: {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())