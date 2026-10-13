"""Reference implementation of the SecureWatch revised policy (paper Table II) and the
scripted scenario / latency evaluation reported in the paper.
Run:  python policy_engine_eval.py     (needs numpy, scikit-learn)"""
import time, json, random
from collections import deque, defaultdict
import numpy as np
from sklearn.ensemble import IsolationForest

KW = ["hack", "spoof", "evil", "fake", "malicious", "attack", "exploit"]
W_KW, W_RATE, W_JUMP, W_ID, W_AN = 40, 25, 35, 30, 30
TAU_Q, DELTA, TAU_R, TH1, TH2 = 5, 10.0, 40, 20, 50

rng = np.random.RandomState(42); random.seed(42)
Xb = np.c_[rng.randint(-95, -35, 2000), rng.poisson(1.5, 2000) + 1]
IF = IsolationForest(contamination=0.02, random_state=42).fit(Xb)

class Engine:
    def __init__(self): self.st = defaultdict(lambda: dict(name=None, rssi=None, ts=deque()))
    def observe(self, mac, name, rssi, t, trusted=False):
        s = self.st[mac]; reasons = []; S = 0
        m = sum(k in (name or "").lower() for k in KW)
        if m: S += W_KW * m; reasons.append(f"+{W_KW*m} keyword x{m}")
        s["ts"].append(t)
        while s["ts"] and t - s["ts"][0] > DELTA: s["ts"].popleft()
        cnt = len(s["ts"])
        if cnt > TAU_Q: S += W_RATE; reasons.append(f"+{W_RATE} request rate")
        if s["rssi"] is not None and abs(rssi - s["rssi"]) > TAU_R: S += W_JUMP; reasons.append(f"+{W_JUMP} RSSI jump")
        if name and s["name"] and name != s["name"]: S += W_ID; reasons.append(f"+{W_ID} identity change")
        if S > 0 and IF.predict([[rssi, cnt]])[0] == -1: S += W_AN; reasons.append(f"+{W_AN} anomaly (corroborated)")
        if name: s["name"] = name
        s["rssi"] = rssi
        cls = "ATTACK" if S >= TH2 else "SUSPICIOUS" if S >= TH1 else ("SAFE" if trusted else "UNVERIFIED")
        return S, cls, reasons

def seq(obs, trusted=False):
    e = Engine(); out = None
    for i, (n, r, t) in enumerate(obs): out = e.observe("AA", n, r, t, trusted)
    return out

R = {}
sc = {}
sc["benign anonymous @-36 dBm"] = seq([(None, -36, 0), (None, -36, 6)])
sc["benign anonymous @-66 dBm"] = seq([(None, -66, 0), (None, -66, 6)])
sc["benign anonymous @-90 dBm"] = seq([(None, -90, 0), (None, -90, 6)])
sc["no name -> name (benign)"] = seq([(None, -60, 0), ("Buds Pro", -61, 6)])
sc["HACK_WATCH_01 (1 keyword)"] = seq([("HACK_WATCH_01", -55, 0)])
sc["HACK_EVIL_SPOOF_WATCH (3 keywords)"] = seq([("HACK_EVIL_SPOOF_WATCH", -55, 0)])
sc["name change Galaxy Watch -> Pixel Watch"] = seq([("Galaxy Watch", -55, 0), ("Pixel Watch", -55, 6)])
sc["RSSI jump -90 -> -30"] = seq([("Band", -90, 0), ("Band", -30, 6)])
sc["request flood (12 adv in 10 s)"] = seq([("Band", -60, i * 0.8) for i in range(12)])
sc["name change + RSSI jump"] = seq([("Galaxy Watch", -90, 0), ("Pixel Watch", -30, 6)])
sc["trusted device with keyword"] = seq([("HACK_WATCH_01", -55, 0)], trusted=True)
R["scenarios"] = {k: dict(score=v[0], cls=v[1], reasons=v[2]) for k, v in sc.items()}

# 50 benign devices x 20 observations
e = Engine(); esc = 0; tot = 0
names = ["Buds Pro", "Watch 5", "Band 7", "Speaker", "TV", None, None, None]
for d in range(50):
    nm = random.choice(names); rssi = random.randint(-90, -40); reveal = random.randint(0, 10)
    for k in range(20):
        rssi = int(np.clip(rssi + rng.normal(0, 4), -95, -35))
        n = nm if (nm and k >= reveal) else None
        S, c, _ = e.observe(f"M{d}", n, rssi, k * 6.0)
        tot += 1; esc += c in ("SUSPICIOUS", "ATTACK")
R["benign50"] = dict(devices=50, observations=tot, escalated=int(esc))

# latency (in-process, single thread)
def lat(stream):
    e = Engine(); ts = []
    for i, (m, n, r, t) in enumerate(stream):
        a = time.perf_counter_ns(); e.observe(m, n, r, t); ts.append((time.perf_counter_ns() - a) / 1000)
    ts = np.array(ts); return dict(n=len(ts), p50=float(np.percentile(ts, 50)), p95=float(np.percentile(ts, 95)), p99=float(np.percentile(ts, 99)))
cur = {j: int(rng.randint(-90, -40)) for j in range(50)}
benign = []
for i in range(50000):
    j = i % 50; cur[j] = int(np.clip(cur[j] + rng.normal(0, 3), -95, -35))
    benign.append((f"M{j}", None, cur[j], i * 0.12))
attack = [(f"A{i%50}", "HACK_WATCH", int(rng.randint(-90, -40)), i * 0.12) for i in range(10000)]
R["latency_benign_us"] = lat(benign); R["latency_attack_us"] = lat(attack)
print(json.dumps(R, indent=1))
