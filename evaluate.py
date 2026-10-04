import json, time,os
from app.db import get_conn
from app.correlator import get_alert, correlate
from app.mitre import map_logs
from app.investigator import investigate

truth = json.load(open("data/eval_truth.json"))
RESULTS = "data/eval_results.json"
prev = {r["id"]: r for r in json.load(open(RESULTS))} if os.path.exists(RESULTS) else {}

def base(tid):
    return tid.split(".")[0]          # compare at technique level (T1110.001 matches T1110)


def score_techniques(pred_ids, expected):
    pred = {base(t) for t in pred_ids}
    allowed = {alt for e in expected for alt in e.split("|")}
    found = sum(1 for e in expected if pred & set(e.split("|")))
    return found, len(expected), len(pred & allowed), len(pred)


rows = []
for aid, gt in truth.items():
    if aid in prev and prev[aid]["llm"] != "error":
        rows.append(prev[aid])
        print(f"{aid:10} (kept from previous run)")
        continue
    conn = get_conn()
    alert = get_alert(conn, aid)
    corr = correlate(conn, alert)
    conn.close()
    rules = map_logs(corr["events"])

    out, secs, err = None, 0.0, None
    for attempt in range(2):                      # one retry if the LLM is busy
        start = time.time()
        try:
            out = investigate(aid)
            secs = time.time() - start
            err = None
            break
        except Exception as e:
            err = str(e)[:100]
            time.sleep(60)

    maxscore = 0
    if corr["all_iocs"]:
        conn = get_conn()
        q = ",".join("?" * len(corr["all_iocs"]))
        maxscore = conn.execute(
            f"SELECT COALESCE(MAX(reputation_score),0) FROM iocs WHERE value IN ({q})",
            corr["all_iocs"]).fetchone()[0]
        conn.close()

    verdict = out["verdict"] if out else "error"
    baseline_b = "true_positive" if (rules and maxscore >= 75) else "false_positive"

    f = e = c = p = 0
    if gt["kind"] == "attack":
        pred_ids = [t["id"] for t in out["mitre_techniques"]] if out else []
        f, e, c, p = score_techniques(pred_ids, gt["techniques"])

    row = {"id": aid, "kind": gt["kind"], "accept": gt["accept"], "llm": verdict,
           "confidence": out["confidence"] if out else None, "baseline_b": baseline_b,
           "llm_ok": verdict in gt["accept"],
           "a_ok": "true_positive" in gt["accept"],
           "b_ok": baseline_b in gt["accept"],
           "secs": round(secs, 1), "found": f, "expected": e, "correct_pred": c, "pred": p,
           "rejected_ids": len(out["rejected_technique_ids"]) if out else 0, "error": err}
    rows.append(row)
    json.dump(list({**prev, **{r["id"]: r for r in rows}}.values()), open(RESULTS, "w"), indent=2)
    print(f"{aid:10} {gt['kind']:7} LLM={verdict:15} B={baseline_b:15} "
          f"{'OK  ' if row['llm_ok'] else 'MISS'} {secs:5.1f}s {err or ''}", flush=True)
    time.sleep(20)                                 # stay under free-tier rate limits

n = len(rows)
attacks = [r for r in rows if r["kind"] == "attack"]
benign = [r for r in rows if r["kind"] == "benign"]
pct = lambda x, y: f"{100 * x / y:.0f}%" if y else "n/a"
done = [r for r in rows if r["llm"] != "error"]

print("\n=========== RESULTS ===========")
print(f"Alerts evaluated: {n} ({len(attacks)} attacks, {len(benign)} benign), LLM errors: {n - len(done)}")
print(f"Verdict accuracy     | AI pipeline {pct(sum(r['llm_ok'] for r in rows), n):>5} | "
      f"A (trust alert) {pct(sum(r['a_ok'] for r in rows), n):>5} | B (rules+TI) {pct(sum(r['b_ok'] for r in rows), n):>5}")
print(f"Attacks caught       | AI pipeline {pct(sum(r['llm'] == 'true_positive' for r in attacks), len(attacks)):>5} | "
      f"A 100% | B {pct(sum(r['baseline_b'] == 'true_positive' for r in attacks), len(attacks)):>5}")
print(f"Benign escalated     | AI pipeline {pct(sum(r['llm'] == 'true_positive' for r in benign), len(benign)):>5} | "
      f"A 100% | B {pct(sum(r['baseline_b'] == 'true_positive' for r in benign), len(benign)):>5}   (lower is better)")
F, E = sum(r["found"] for r in attacks), sum(r["expected"] for r in attacks)
C, P = sum(r["correct_pred"] for r in attacks), sum(r["pred"] for r in attacks)
print(f"MITRE recall {pct(F, E)} ({F}/{E}) | MITRE precision {pct(C, P)} ({C}/{P}) | "
      f"invalid IDs rejected: {sum(r['rejected_ids'] for r in rows)}")
if done:
    print(f"Average investigation time: {sum(r['secs'] for r in done) / len(done):.1f} s")
json.dump(rows, open("data/eval_results.json", "w"), indent=2)
json.dump(list({**prev, **{r["id"]: r for r in rows}}.values()), open(RESULTS, "w"), indent=2)
print("Saved data/eval_results.json")