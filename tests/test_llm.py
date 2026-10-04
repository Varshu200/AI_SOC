from app.llm import client, MODEL
try:
    r = client().models.generate_content(model=MODEL, contents="Reply with the word ok")
    print("WORKS:", r.text)
except Exception as e:
    print(e)