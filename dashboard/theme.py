import html
import streamlit as st

PURPLE, INDIGO, GREEN, ORANGE, RED = "#8b5cf6", "#6366f1", "#10b981", "#f59e0b", "#ef4444"
SEV = {"critical": RED, "high": ORANGE, "medium": "#eab308", "low": GREEN}
VERDICT = {"malicious": RED, "suspicious": ORANGE, "clean": GREEN, "unknown": "#94a3b8"}
PRIO = {"immediate": RED, "high": ORANGE, "medium": "#eab308", "low": GREEN}

CSS = """<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;700;800&display=swap');
html, body, .stApp, button, input { font-family: 'DM Sans', sans-serif; }
.stApp { background: radial-gradient(900px 520px at 50% -8%, rgba(124,58,237,.30), transparent 70%), #0d0b1a; }
header[data-testid="stHeader"] { background: transparent; }
.block-container { max-width: 1150px; padding-top: 2rem; }
.hero { text-align: center; padding: 1.2rem 0 .4rem; }
.pill { display: inline-block; padding: 6px 16px; border-radius: 999px; border: 1px solid rgba(255,255,255,.14); background: rgba(255,255,255,.04); color: #c9c4e6; font-size: .85rem; }
.hero-title { font-size: 3.1rem; line-height: 1.12; font-weight: 800; margin: 1rem 0 .6rem; color: #cfcfd6; }
.hero-title span { background: linear-gradient(90deg, #c4a8ff, #f0d9ff); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.hero-sub { color: #9a97b5; max-width: 640px; margin: 0 auto; font-size: 1.05rem; }
.flow { display: flex; flex-wrap: wrap; justify-content: center; gap: 8px; margin: 1.4rem 0 1.6rem; }
.step { padding: 7px 14px; border-radius: 999px; border: 1px solid rgba(139,92,246,.45); background: rgba(139,92,246,.10); color: #ddd6fe; font-size: .85rem; }
.step b { color: #a78bfa; margin-right: 6px; }
.arrow { color: #6b6890; align-self: center; }
.card { background: rgba(255,255,255,.04); border: 1px solid rgba(255,255,255,.08); border-radius: 18px; padding: 16px 18px; margin-bottom: 12px; color: #d8d4f0; }
.kpi { border-top: 3px solid var(--c); min-height: 118px; }
.kpi .ic { width: 38px; height: 38px; border-radius: 10px; display: grid; place-items: center; background: rgba(139,92,246,.16); margin-bottom: 10px; }
.kpi .lb { color: #9a97b5; font-size: .85rem; }
.kpi .vl { font-size: 2rem; font-weight: 700; color: #f3f1ff; }
.chip { display: inline-block; padding: 3px 12px; border-radius: 999px; font-size: .78rem; font-weight: 700; border: 1px solid var(--c); color: var(--c); margin-right: 6px; }
.tag { display: inline-block; padding: 2px 10px; border-radius: 8px; font-size: .75rem; background: rgba(255,255,255,.07); color: #bdb8dd; margin-right: 6px; }
.muted { color: #9a97b5; font-size: .85rem; margin-top: 6px; }
.vcard { display: flex; gap: 22px; align-items: center; border-left: 4px solid var(--c); }
.vtitle { font-size: 1.9rem; font-weight: 800; color: #f3f1ff; margin-bottom: 4px; }
.vsum { color: #c9c4e6; margin-top: 10px; }
.ring { flex: none; width: 96px; height: 96px; border-radius: 50%; background: conic-gradient(#8b5cf6 calc(var(--p) * 1%), rgba(255,255,255,.08) 0); display: grid; place-items: center; }
.ring-in { width: 76px; height: 76px; border-radius: 50%; background: #0d0b1a; display: grid; place-items: center; font-weight: 700; color: #f3f1ff; font-size: 1.2rem; }
.ev { border-left: 3px solid #8b5cf6; }
.tl { margin: 6px 0 0 8px; border-left: 2px solid rgba(139,92,246,.4); padding-left: 24px; }
.tl-item { position: relative; margin-bottom: 16px; }
.tl-dot { position: absolute; left: -31px; top: 5px; width: 12px; height: 12px; border-radius: 50%; background: #8b5cf6; box-shadow: 0 0 0 4px rgba(139,92,246,.25); }
.tl-meta { color: #a78bfa; font-size: .8rem; font-weight: 700; }
.tl-main { color: #f3f1ff; }
.tl code { display: block; margin-top: 4px; padding: 6px 10px; border-radius: 8px; background: rgba(0,0,0,.35); color: #c4b5fd; font-size: .8rem; white-space: pre-wrap; word-break: break-all; }
.bar { height: 8px; border-radius: 99px; background: rgba(255,255,255,.08); overflow: hidden; margin-top: 10px; }
.bar > div { height: 100%; border-radius: 99px; }
.mid { color: #c4b5fd !important; font-weight: 700; margin-right: 8px; text-decoration: none; }
.stButton > button { background: linear-gradient(90deg, #7c3aed, #a855f7); color: #fff; border: 0; border-radius: 12px; padding: .6rem 1.5rem; font-weight: 700; }
.stButton > button:hover { filter: brightness(1.12); color: #fff; }
button[data-baseweb="tab"] { border-radius: 999px; padding: 6px 16px; }
button[data-baseweb="tab"][aria-selected="true"] { background: rgba(139,92,246,.22); color: #ddd6fe; }
div[data-baseweb="tab-highlight"] { display: none; }
[data-testid="stDataFrame"] { border-radius: 14px; overflow: hidden; }
</style>"""

STEPS = ["Alert", "IOC extraction", "Threat intel", "Log correlation", "MITRE mapping", "AI verdict"]


def esc(x):
    return html.escape(str(x if x is not None else ""))


def hero():
    st.markdown(
        '<div class="hero"><div class="pill">✦ AI + SIEM logs + Threat Intelligence + MITRE ATT&amp;CK</div>'
        '<h1 class="hero-title">Investigate Alerts<br><span>In Seconds, Not Hours</span></h1>'
        '<p class="hero-sub">Your AI SOC analyst correlates logs, checks indicators, maps attacks '
        'and recommends a response, so humans can focus on the decisions.</p></div>',
        unsafe_allow_html=True)


def pipeline():
    items = '<span class="arrow">→</span>'.join(
        f'<span class="step"><b>{i}</b>{esc(s)}</span>' for i, s in enumerate(STEPS, 1))
    st.markdown(f'<div class="flow">{items}</div>', unsafe_allow_html=True)


def kpi(label, value, color, icon):
    return (f'<div class="card kpi" style="--c:{color}"><div class="ic">{icon}</div>'
            f'<div class="lb">{esc(label)}</div><div class="vl">{esc(value)}</div></div>')


def verdict_card(r):
    sev = r["severity"]
    c = SEV.get(sev, PURPLE)
    pct = int(round(r["confidence"] * 100))
    verdict = r["verdict"].replace("_", " ").title()
    return (f'<div class="card vcard" style="--c:{c}">'
            f'<div class="ring" style="--p:{pct}"><div class="ring-in">{pct}%</div></div>'
            f'<div><div class="vtitle">{esc(verdict)}</div>'
            f'<span class="chip" style="--c:{c}">{esc(sev.upper())}</span>'
            f'<span class="chip" style="--c:{PURPLE}">MODEL CONFIDENCE</span>'
            f'<div class="vsum">{esc(r["summary"])}</div></div></div>')


def evidence(items):
    return "".join(f'<div class="card ev">{esc(e)}</div>' for e in items)


def timeline(items):
    rows = ""
    for i, t in enumerate(items, 1):
        cnt = f" ×{t['count']}" if t["count"] > 1 else ""
        rows += (f'<div class="tl-item"><div class="tl-dot"></div>'
                 f'<div class="tl-meta">T{i} · {esc(t["start"])}{cnt} · {esc(t["event_type"])}</div>'
                 f'<div class="tl-main">{esc(t["user"])} · {esc(t["src_ip"])} → {esc(t["dst_ip"])}</div>'
                 f'<code>{esc(t["sample"])}</code></div>')
    return f'<div class="tl">{rows}</div>'


def ioc_cards(iocs):
    out = ""
    for i in iocs:
        c = VERDICT.get(i["verdict"], "#94a3b8")
        s = max(0, min(100, int(i["reputation_score"])))
        out += (f'<div class="card"><b style="color:#f3f1ff">{esc(i["value"])}</b> '
                f'<span class="tag">{esc(i["type"])}</span>'
                f'<span class="chip" style="--c:{c}">{esc(i["verdict"].upper())}</span>'
                f'<div class="bar"><div style="width:{s}%;background:{c}"></div></div>'
                f'<div class="muted">reputation {s}/100 · source: {esc(i.get("source") or "none")}</div></div>')
    return out


def mitre_cards(techs):
    out = ""
    for t in techs:
        url = "https://attack.mitre.org/techniques/" + t["id"].replace(".", "/") + "/"
        tactics = "".join(f'<span class="tag">{esc(x)}</span>' for x in t["tactics"])
        out += (f'<div class="card"><a class="mid" href="{esc(url)}" target="_blank">{esc(t["id"])}</a>'
                f'<b style="color:#f3f1ff">{esc(t["name"])}</b>'
                f'<div style="margin-top:6px">{tactics}</div>'
                f'<div class="muted">{esc(t["reason"])}</div></div>')
    return out


def action_cards(actions):
    order = {"immediate": 0, "high": 1, "medium": 2, "low": 3}
    out = ""
    for a in sorted(actions, key=lambda x: order.get(x["priority"], 9)):
        c = PRIO.get(a["priority"], PURPLE)
        out += (f'<div class="card" style="border-left:4px solid {c}">'
                f'<span class="chip" style="--c:{c}">{esc(a["priority"].upper())}</span>'
                f'<span class="tag">{esc(a["type"])}</span>'
                f'<div style="margin-top:8px">{esc(a["action"])}</div></div>')
    return out