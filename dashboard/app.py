import requests
import pandas as pd
import streamlit as st

API = "http://127.0.0.1:8000"
st.set_page_config(page_title="AI SOC", page_icon="🛡️", layout="wide")

SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def api_get(path):
    try:
        r = requests.get(f"{API}{path}", timeout=15)
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()
    except requests.exceptions.ConnectionError:
        st.error("Cannot reach the API. Start it in another terminal: `uvicorn app.main:app --reload`")
        st.stop()


def mitre_url(tid):
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


# ---------------- Header and overview ----------------
st.title("🛡️ AI SOC Investigation Assistant")
st.caption("AI + SIEM logs + threat intelligence + MITRE ATT&CK, combined into automated investigations")

stats = api_get("/stats")
alerts = api_get("/alerts") or []

m1, m2, m3, m4 = st.columns(4)
m1.metric("Alerts", stats["alerts_total"])
m2.metric("Investigated", stats["alerts_by_status"].get("investigated", 0))
m3.metric("Critical findings", stats["by_severity"].get("critical", 0))
m4.metric("Malicious IOCs", len(stats["malicious_iocs"]))

if stats["investigations_total"]:
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("Investigations by severity")
        st.bar_chart(pd.Series(stats["by_severity"], name="count"))
    with c2:
        st.subheader("Top ATT&CK techniques")
        tech = pd.DataFrame(stats["top_techniques"], columns=["technique", "count"]).set_index("technique")
        st.bar_chart(tech)

st.divider()

# ---------------- Alert queue ----------------
st.subheader("Alert queue")
if not alerts:
    st.info("No alerts yet.")
    st.stop()

st.dataframe(
    pd.DataFrame(alerts)[["alert_id", "timestamp", "rule_name", "host", "severity_hint", "status"]],
    use_container_width=True, hide_index=True)

alert_id = st.selectbox("Select an alert to investigate", [a["alert_id"] for a in alerts])
alert = next(a for a in alerts if a["alert_id"] == alert_id)
st.write(f"**{alert['rule_name']}** on `{alert['host']}`: {alert['description']}")

if st.button("🔍 Run investigation", type="primary"):
    with st.spinner("Correlating logs, checking threat intel, asking the LLM... (up to ~1 minute)"):
        try:
            r = requests.post(f"{API}/investigate/{alert_id}", timeout=240)
        except requests.exceptions.RequestException as e:
            st.error(f"Request failed: {e}")
            st.stop()
    if r.status_code != 200:
        st.error(r.json().get("detail", r.text))
        st.stop()
    st.rerun()

# ---------------- Investigation report ----------------
report = api_get(f"/alerts/{alert_id}/investigation")
if not report:
    st.info("This alert has not been investigated yet. Click the Run investigation button.")
    st.stop()

st.divider()
st.subheader("Investigation report")
a, b, c = st.columns(3)
a.metric("Verdict", report["verdict"].replace("_", " ").title())
b.metric("Severity", f"{SEV_ICON.get(report['severity'], '')} {report['severity'].title()}")
c.metric("Model confidence", f"{report['confidence']:.0%}")
st.write(report["summary"])
st.caption("Confidence is the model's own estimate, not a measured probability. "
           "Recommended actions need human approval.")

tab_ev, tab_tl, tab_ioc, tab_mitre, tab_act = st.tabs(
    ["Evidence", "Timeline", "IOCs", "MITRE ATT&CK", "Response actions"])

with tab_ev:
    for e in report["key_evidence"]:
        st.markdown(f"- {e}")

with tab_tl:
    tl = pd.DataFrame(report["timeline"])
    tl.insert(0, "ref", [f"T{i}" for i in range(1, len(tl) + 1)])
    st.dataframe(tl[["ref", "start", "end", "count", "event_type", "user", "src_ip", "dst_ip", "sample"]],
                 use_container_width=True, hide_index=True)

with tab_ioc:
    ioc = pd.DataFrame(report["iocs"])
    st.dataframe(ioc[["value", "type", "verdict", "reputation_score", "source"]],
                 use_container_width=True, hide_index=True)
    with st.expander("Raw threat-intel details"):
        for i in report["iocs"]:
            st.markdown(f"**{i['value']}**")
            st.json(i["details"])

with tab_mitre:
    mt = pd.DataFrame(report["mitre_techniques"])
    if not mt.empty:
        mt["tactics"] = mt["tactics"].apply(lambda x: ", ".join(x))
        mt["link"] = mt["id"].apply(mitre_url)
        st.dataframe(mt[["id", "name", "tactics", "reason", "link"]],
                     use_container_width=True, hide_index=True,
                     column_config={"link": st.column_config.LinkColumn("MITRE page")})
    if report["rejected_technique_ids"]:
        st.warning(f"Rejected invalid technique IDs: {report['rejected_technique_ids']}")

with tab_act:
    act = pd.DataFrame(report["recommended_actions"])
    order = {"immediate": 0, "high": 1, "medium": 2, "low": 3}
    act = act.sort_values("priority", key=lambda s: s.map(order))
    st.dataframe(act[["priority", "type", "action"]], use_container_width=True, hide_index=True)