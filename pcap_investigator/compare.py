"""
Objective 5 - Compare our paper-inspired request rules with correlation.

Uses pcaps/labels.json (ground truth: which destinations are malicious).
  Paper approach    : a request is malicious if its score >= threshold.
  Improved approach : a request is malicious if it belongs to a MEDIUM/HIGH
                      correlated incident.
Usage:  python compare.py pcaps/normal_browsing.pcap pcaps/infected_host.pcap
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from main import analyse


def metrics(pred, truth):
    tp = sum(p and t for p, t in zip(pred, truth))
    fp = sum(p and not t for p, t in zip(pred, truth))
    fn = sum(t and not p for p, t in zip(pred, truth))
    tn = len(pred) - tp - fp - fn
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return dict(TP=tp, FP=fp, FN=fn, TN=tn, Precision=precision, Recall=recall, F1=f1)


def main(pcaps):
    labels = json.load(open("pcaps/labels.json"))
    bad = set(labels["malicious_destinations"])
    rows = []
    for pcap in pcaps:
        requests, incidents = analyse(pcap)
        truth = [(r["host"] or r["dst_ip"]) in bad for r in requests]
        paper_pred = [r["paper_flag"] for r in requests]
        in_incident = {f for i in incidents if i["severity"] in ("HIGH", "MEDIUM") for f in i["frames"]}
        improved_pred = [r["frame"] in in_incident for r in requests]
        name = os.path.basename(pcap)
        for approach, pred, alerts in (("Feature rules (per-request)", paper_pred, sum(paper_pred)),
                                       ("Improved (correlated)", improved_pred,
                                        sum(i["severity"] in ("HIGH", "MEDIUM") for i in incidents))):
            m = metrics(pred, truth)
            rows.append({"PCAP": name, "Approach": approach, "Requests": len(requests),
                         "Malicious": sum(truth), "Alerts to review": alerts, **m})

    hdr = ["PCAP", "Approach", "Requests", "Malicious", "TP", "FP", "FN",
           "Precision", "Recall", "F1", "Alerts to review"]
    lines = ["| " + " | ".join(hdr) + " |", "|" + "---|" * len(hdr)]
    for r in rows:
        lines.append("| " + " | ".join(f"{r[h]:.2f}" if isinstance(r[h], float) else str(r[h]) for h in hdr) + " |")
    table = "\n".join(lines)
    print(table)
    os.makedirs("output", exist_ok=True)
    with open("output/comparison.md", "w") as fh:
        fh.write("# Feature rules vs correlated incidents\n\nGenerated, labelled captures only; not a real-world malware accuracy estimate.\n\n" + table + "\n")

    # chart for the presentation (infected capture only)
    inf = [r for r in rows if r["Malicious"] > 0]
    if inf:
        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        names = [r["Approach"] for r in inf]
        colors = ["#9aa5b8", "#3f51b5"]
        x = range(3)
        for k, r in enumerate(inf):
            axes[0].bar([i + k * 0.38 for i in x], [r["Precision"], r["Recall"], r["F1"]],
                        width=0.38, color=colors[k], label=names[k])
        axes[0].set_xticks([i + 0.19 for i in x], ["Precision", "Recall", "F1"])
        axes[0].set_ylim(0, 1.1)
        axes[0].set_title("Detection quality (infected_host.pcap)")
        axes[0].legend(frameon=False, fontsize=9, loc="upper center", bbox_to_anchor=(0.5, -0.1), ncol=2)
        axes[1].bar(names, [r["Alerts to review"] for r in inf], color=colors)
        axes[1].set_title("Alerts an analyst must review")
        for i, r in enumerate(inf):
            axes[1].text(i, r["Alerts to review"] + 0.3, str(r["Alerts to review"]), ha="center")
        for ax in axes:
            ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout()
        fig.savefig("output/comparison_chart.png", dpi=150)
        print("saved output/comparison.md and output/comparison_chart.png")


if __name__ == "__main__":
    main(sys.argv[1:] or ["pcaps/normal_browsing.pcap", "pcaps/infected_host.pcap"])
