import json
from app.db import get_conn
from app.correlator import get_alert, correlate
from app.mitre import map_logs

truth = json.load(open("data/eval_truth.json"))
conn = get_conn()
hit = tot = 0
for aid, gt in truth.items():
    if gt["kind"] != "attack":
        continue
    corr = correlate(conn, get_alert(conn, aid))
    pred = {t.split(".")[0] for t in map_logs(corr["events"])}
    found = sum(1 for e in gt["techniques"] if pred & set(e.split("|")))
    print(f"{aid:10} found {found}/{len(gt['techniques'])}  predicted: {sorted(pred)}")
    tot += len(gt["techniques"])
    hit += found
print(f"\nRule-only MITRE recall: {hit}/{tot}")