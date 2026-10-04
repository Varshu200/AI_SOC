import re, ipaddress

PATTERNS = {
    "ipv4":   r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "domain": r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b",
    "md5":    r"\b[a-fA-F0-9]{32}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "url":    r"https?://[^\s\"'<>]+",
    "email":  r"\b[\w.+-]+@[\w-]+\.[\w.]+\b",
}
FILE_EXTS = {"sh", "exe", "py", "txt", "dll", "bat", "ps1", "js", "log", "json",
             "gz", "tgz", "zip", "tar", "sql", "conf", "bin", "so", "yml", "yaml"}
def refang(text):
    return (text.replace("hxxp", "http").replace("[.]", ".")
                .replace("(.)", ".").replace("[at]", "@"))

def is_public_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_multicast)
    except ValueError:
        return False

def extract_iocs(text):
    text = refang(text)
    found = {k: set(re.findall(v, text, re.I)) for k, v in PATTERNS.items()}
    found["ipv4"] = {i for i in found["ipv4"] if is_public_ip(i)}
    found["domain"] = {d.lower() for d in found["domain"]
                       if d.rsplit(".", 1)[-1].lower() not in FILE_EXTS
                       and not re.fullmatch(r"(?:\d+\.)+\d+", d)}
    return {k: sorted(v) for k, v in found.items() if v}