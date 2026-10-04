from app.investigator import investigate

r = investigate("ALERT-001")
print("VERDICT   :", r["verdict"], "| severity:", r["severity"], "| confidence:", r["confidence"])
print("SUMMARY   :", r["summary"])
print("\nEVIDENCE:")
for e in r["key_evidence"]:
    print("  -", e)
print("\nMITRE:")
for t in r["mitre_techniques"]:
    print("  ", t["id"], t["name"], "|", t["reason"])
print("  rejected (not real ATT&CK IDs):", r["rejected_technique_ids"])
print("\nACTIONS:")
for a in r["recommended_actions"]:
    print(f"  [{a['priority']}/{a['type']}] {a['action']}")