import os
from dotenv import load_dotenv
from google import genai

load_dotenv()
c = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
SKIP = ("image", "tts", "live", "audio", "embedding", "robotics", "vision")

for m in c.models.list():
    name = m.name.replace("models/", "")
    if "flash" not in name or any(s in name for s in SKIP):
        continue
    try:
        c.models.generate_content(model=name, contents="Reply with the word ok")
        print("WORKS  ", name)
    except Exception as e:
        s = str(e)
        why = "daily quota used" if "PerDay" in s else "minute limit" if "PerMinute" in s else s[:70]
        print("BLOCKED", name, "-", why)