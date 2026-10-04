import os, re, json,time
from google.genai import errors
from typing import List, Literal
from dotenv import load_dotenv
from google import genai
from google.genai import types
from pydantic import BaseModel, Field, ValidationError
from app.mitre import get_technique

load_dotenv()
MODEL = os.getenv("LLM_MODEL", "gemini-3.8-flash")
_client = None


def client():
    global _client
    if _client is None:
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY is missing from .env")
        _client = genai.Client(api_key=key)
    return _client


# ---------- Output schema (Pydantic rejects anything that doesn't fit) ----------
class Technique(BaseModel):
    id: str
    reason: str

class Action(BaseModel):
    action: str
    priority: Literal["immediate", "high", "medium", "low"]
    type: Literal["contain", "eradicate", "recover", "monitor"]

class Report(BaseModel):
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    summary: str
    key_evidence: List[str]
    mitre_techniques: List[Technique]
    recommended_actions: List[Action]


SYSTEM = """You are a Tier-2 SOC analyst assistant. Investigate the alert using ONLY the evidence provided.
Rules:
- Never invent IPs, domains, hosts, users or events that are not in the evidence.
- A threat-intel verdict of "unknown" means no data, NOT safe.
- Cite evidence using timeline labels like [T1], [T2] and IOC values.
- mitre_techniques should use IDs from the candidate list unless the evidence clearly supports another real ATT&CK ID.
- If the evidence is insufficient, use verdict "needs_review" and a lower confidence.
- Recommended actions are suggestions for a human analyst to approve, not automatic actions.
- Respond with a single JSON object and nothing else (no markdown fences)."""

SCHEMA = """{
 "verdict": "true_positive | false_positive | needs_review",
 "severity": "low | medium | high | critical",
 "confidence": 0.0 to 1.0,
 "summary": "2-3 sentences",
 "key_evidence": ["each item cites [T#] or an IOC value"],
 "mitre_techniques": [{"id": "T####", "reason": "..."}],
 "recommended_actions": [{"action": "...", "priority": "immediate|high|medium|low", "type": "contain|eradicate|recover|monitor"}]
}"""


def build_prompt(alert, iocs, timeline, candidates):
    tl = "\n".join(
        f"[T{i}] {t['start']} -> {t['end']} x{t['count']} {t['event_type']} "
        f"user={t['user']} {t['src_ip']}->{t['dst_ip']} | {t['sample']}"
        for i, t in enumerate(timeline, 1))
    ioc_lines = "\n".join(
        f"- {i['value']} ({i['type']}): verdict={i['verdict']}, score={i['reputation_score']}, "
        f"details={json.dumps(i['details'])}" for i in iocs)
    cand = "\n".join(f"- {tid} {c['name']}: {c['why']}" for tid, c in candidates.items()) or "- none"
    return f"""ALERT
id: {alert['alert_id']}
rule: {alert['rule_name']}
host: {alert['host']}
time: {alert['timestamp']}
description: {alert['description']}

THREAT INTELLIGENCE
{ioc_lines}

CORRELATED TIMELINE
{tl}

CANDIDATE ATT&CK TECHNIQUES (from detection rules)
{cand}

Return JSON in exactly this shape:
{SCHEMA}"""


def _extract_json(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        raise ValueError("no JSON object found in the reply")
    return m.group(0)

FALLBACKS = [m.strip() for m in os.getenv("LLM_FALLBACK_MODELS", "").split(",") if m.strip()]


_dead = set()          # models whose quota is exhausted or that don't exist, skipped for this run


def _generate(contents, config):
    """Call the LLM; retry temporary errors, skip models that are out of quota, then try fallbacks."""
    last = None
    for model in [MODEL] + FALLBACKS:
        if model in _dead:
            continue
        for attempt in range(4):
            try:
                return client().models.generate_content(model=model, contents=contents, config=config)
            except errors.ServerError as e:            # 503 etc: temporary, wait and retry
                last = e
                time.sleep(2 ** (attempt + 1))         # 2, 4, 8, 16 seconds
            except errors.ClientError as e:
                last = e
                if e.code == 429:
                    if "PerDay" in str(e):             # daily quota gone: stop using this model
                        _dead.add(model)
                        break
                    time.sleep(20)                     # per-minute limit: wait and retry
                elif e.code == 404:                    # model name not available: try the next one
                    _dead.add(model)
                    break
                else:
                    raise                              # 400/401 etc. are real errors
    raise RuntimeError(f"LLM unavailable after retries: {last}")

def ask_llm(prompt):
    config = types.GenerateContentConfig(
        system_instruction=SYSTEM,
        response_mime_type="application/json",
        max_output_tokens=4096,
    )
    text, last_err = "", None
    for attempt in range(2):                      # one retry if the output is invalid
        contents = prompt
        if attempt == 1:
            contents = (f"{prompt}\n\nYour previous reply was invalid ({last_err}).\n"
                        f"Previous reply:\n{text}\n\nReturn ONLY the corrected JSON object.")
        resp = _generate(contents, config) 
        text = resp.text or ""
        try:
            return Report.model_validate_json(_extract_json(text))
        except (ValueError, ValidationError) as e:
            last_err = e
    raise RuntimeError(f"LLM output invalid after retry: {last_err}")


def validate_techniques(report):
    """Keep only technique IDs that exist in the real ATT&CK data."""
    good, rejected = [], []
    for t in report.mitre_techniques:
        tech = get_technique(t.id)
        if tech:
            good.append({"id": t.id, "name": tech["name"],
                         "tactics": tech["tactics"], "reason": t.reason})
        else:
            rejected.append(t.id)
    return good, rejected