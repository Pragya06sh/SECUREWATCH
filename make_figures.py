"""Generates paper Figures 1, 2, 4 and 6 as PNG (300 dpi).
Run from the repo's backend folder:   python make_figures.py
Needs: matplotlib, numpy, pandas, scikit-learn. Output: ./figures/"""
import os, io, contextlib, sys
import numpy as np, pandas as pd
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = "figures"; os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 6.5, "savefig.dpi": 300})
NAVY, CYAN, GREEN, GREY, AMBER, RED, PURPLE = "#0A1020", "#0891B2", "#059669", "#64748B", "#D97706", "#DC2626", "#7C3AED"
TINT = dict(cyan="#E0F2FE", green="#D1FAE5", grey="#E2E8F0", amber="#FEF3C7", red="#FEE2E2", purple="#EDE9FE", navy="#DBE4F0")

def box(ax, x, y, w, h, text, fc, ec, fs=6.5, bold=False, color="#0F172A", lw=0.9):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0,rounding_size=1.2", fc=fc, ec=ec, lw=lw))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", color=color, linespacing=1.25)

def arrow(ax, p, q, color=GREY, lw=0.9, style="-|>", ms=6):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=ms, lw=lw, color=color, shrinkA=0, shrinkB=0))

# ---------------- Figure 1: architecture (full width) ----------------
fig, ax = plt.subplots(figsize=(7.16, 2.3)); ax.set_xlim(0, 100); ax.set_ylim(0, 32); ax.axis("off")
box(ax, 0.5, 9, 14.5, 14, "BLE devices\n\nwatch · earbuds\nphone · speaker", TINT["grey"], GREY, fs=6)
box(ax, 21, 9, 14, 14, "Edge scanner\n\nlaptop (Bleak)\nAndroid client", TINT["cyan"], CYAN, fs=6)
ax.add_patch(FancyBboxPatch((41, 1.2), 28, 29.4, boxstyle="round,pad=0,rounding_size=1.2", fc=TINT["navy"], ec=NAVY, lw=1.1))
ax.text(55, 27.4, "Detection engine (FastAPI)", ha="center", va="center", fontsize=7, fontweight="bold", color=NAVY)
for k, t in enumerate(["1  Device identification", "2  Behaviour features", "3  Risk scoring + ML models", "4  Four-class decision"]):
    box(ax, 43.5, 19.4 - k * 5.2, 23, 4, t, "white", GREY, fs=6, lw=0.6)
box(ax, 74, 21.5, 14, 6.5, "Quarantine", TINT["red"], RED, bold=True)
box(ax, 74, 12.7, 14, 6.5, "Alert", TINT["amber"], AMBER, bold=True)
box(ax, 74, 3.9, 14, 6.5, "Audit ledger\n(SHA-256 chain)", TINT["purple"], PURPLE, fs=5.6)
box(ax, 91, 9, 8.8, 14, "Live\ndashboard", TINT["green"], GREEN, bold=True, fs=5.0)
arrow(ax, (15, 16), (21, 16)); ax.text(18, 17.2, "adv.\npackets", ha="center", va="bottom", fontsize=5.2, color=GREY, style="italic")
arrow(ax, (35, 16), (41, 16)); ax.text(38, 17.2, "events", ha="center", va="bottom", fontsize=5.2, color=GREY, style="italic")
for y in (24.7, 15.9, 7.1): arrow(ax, (69, 16), (74, y), color=NAVY)
for y in (24.7, 15.9, 7.1): arrow(ax, (88, y), (91, 16), color=NAVY)
fig.savefig(f"{OUT}/fig1_architecture.png", bbox_inches="tight", pad_inches=0.04); plt.close(fig)

# ---------------- Figure 2: identification ladder (single column) ----------------
fig, ax = plt.subplots(figsize=(3.4, 2.75)); ax.set_xlim(0, 100); ax.set_ylim(0, 92); ax.axis("off")
steps = [("1  Name keyword", "Brand\n(name keyword)", TINT["cyan"], CYAN),
         ("2  Company ID", "Vendor\n(SIG company ID)", TINT["cyan"], CYAN),
         ("3  Service UUID", "Device type\n(e.g. health monitor)", TINT["cyan"], CYAN),
         ("4  OUI prefix\n(public address only)", "Vendor\n(OUI table)", TINT["cyan"], CYAN),
         ("5  No evidence", "Unidentified\n(never guessed)", TINT["amber"], AMBER)]
H, G = 12.5, 5.5
for k, (l, r, fc, ec) in enumerate(steps):
    y = 92 - 2 - H - k * (H + G)
    box(ax, 1, y, 46, H, l, "white", ec, fs=6.2, lw=1.0)
    box(ax, 58, y, 41, H, r, fc, ec, fs=5.8, lw=1.0)
    arrow(ax, (47, y + H / 2), (58, y + H / 2), color=GREEN if k < 4 else AMBER)
    ax.text(52.5, y + H / 2 + 2.6, "match" if k < 4 else "stop", ha="center", fontsize=4.8, color=GREEN if k < 4 else AMBER, style="italic")
    if k < 4:
        arrow(ax, (24, y), (24, y - G), color=GREY); ax.text(26, y - G / 2, "no match", fontsize=4.8, color=GREY, va="center", style="italic")
fig.savefig(f"{OUT}/fig2_identification.png", bbox_inches="tight", pad_inches=0.04); plt.close(fig)

# ---------------- Figure 4: ledger with REAL hashes from blockchain.py ----------------
sys.path.insert(0, ".")
from blockchain import Blockchain
with contextlib.redirect_stdout(io.StringIO()):
    bc = Blockchain()
    bc.add_block({"event": "ATTACK", "device": "HACK_EVIL_SPOOF_WATCH"})
    bc.add_block({"event": "BLOCK", "device": "C0:09:D0:27:FD:0A"})
    bc.add_block({"event": "ATTACK", "device": "FLOOD_DEVICE_07"})
B = bc.chain[1:4]
EV = [b.data["event"] for b in B]
HS = [b.hash for b in B]
PV = [b.previous_hash for b in B]
short = lambda h: h[:8]
tampered_stored = B[1].hash
B[1].data = {"event": "SAFE", "device": "HACK_EVIL_SPOOF_WATCH"}
recomputed = B[1].calculate_hash()
assert recomputed != tampered_stored
fig, ax = plt.subplots(figsize=(3.4, 2.5)); ax.set_xlim(0, 100); ax.set_ylim(0, 80); ax.axis("off")
def row(y0, bad, title, tcolor):
    ax.text(1, y0 + 29, title, fontsize=6.0, fontweight="bold", color=tcolor, va="bottom", linespacing=1.3)
    for i, b in enumerate(B):
        x = 1 + i * 34
        isbad = bad and i == 1
        ev = "SAFE*" if isbad else EV[i]
        lines = f"Block {b.index}\nevent: {ev}\nprev: {short(PV[i])}\nhash: {short(HS[i])}"
        if isbad: lines += f"\nrecomp: {short(recomputed)}"
        box(ax, x, y0 + (2 if isbad else 4), 29, 24 if isbad else 22, lines, TINT["red"] if isbad else TINT["green"], RED if isbad else GREEN, fs=5.2, lw=1.1 if isbad else 0.9)
        if i < 2: arrow(ax, (x + 29, y0 + 15), (x + 34, y0 + 15), color=GREY)
row(46, False, "(a) Valid chain: every hash and link matches", GREEN)
row(2, True, "(b) Block 2 edited after the fact (*):\nrecomputed hash differs, tamper located at index 2", RED)
fig.savefig(f"{OUT}/fig4_ledger.png", bbox_inches="tight", pad_inches=0.04); plt.close(fig)
print("ledger demo hashes:", [short(b.hash) for b in bc.chain[1:4]], "recomputed", short(recomputed))

# ---------------- Figure 6: ToN-IoT confusion matrix + top features (real run) ----------------
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
n = pd.read_csv("data/train_test_network.csv")
X = n.select_dtypes(include=[np.number]).drop(columns=["label"], errors="ignore"); y = n["label"]
Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)
rf = RandomForestClassifier(n_estimators=300, random_state=42, n_jobs=-1).fit(Xtr, ytr)
cm = confusion_matrix(yte, rf.predict(Xte)); print("confusion matrix:", cm.tolist())
imp = pd.Series(rf.feature_importances_, index=X.columns).sort_values(ascending=False).head(5)[::-1]
fig, (a1, a2) = plt.subplots(1, 2, figsize=(3.5, 2.0), gridspec_kw={"width_ratios": [1, 1.15], "wspace": 0.75})
a1.imshow(cm / cm.sum(axis=1, keepdims=True), cmap="Blues", vmin=0, vmax=1)
for i in range(2):
    for j in range(2):
        a1.text(j, i, f"{cm[i, j]:,}", ha="center", va="center", fontsize=6.5, fontweight="bold",
                color="white" if cm[i, j] / cm[i].sum() > 0.5 else "#0F172A")
a1.set_xticks([0, 1]); a1.set_yticks([0, 1]); a1.set_xticklabels(["normal", "attack"]); a1.set_yticklabels(["normal", "attack"], rotation=90, va="center")
a1.set_xlabel("Predicted", fontsize=6.5); a1.set_ylabel("True", fontsize=6.5); a1.set_title("(a) Confusion matrix", fontsize=6.8, fontweight="bold")
a2.barh(imp.index, imp.values, color=CYAN); a2.set_title("(b) Top-5 features", fontsize=6.8, fontweight="bold")
a2.set_xlabel("Importance", fontsize=6.5); a2.tick_params(labelsize=6)
for s in ("top", "right"): a2.spines[s].set_visible(False)
fig.savefig(f"{OUT}/fig6_ton_results.png", bbox_inches="tight", pad_inches=0.04); plt.close(fig)
print("done ->", OUT)
