"""Suggested fix code snippets keyed by rule-ish title substrings."""
from typing import Optional

SNIPPETS = {
    "hard-coded secret": '''# Bad\nAPI_KEY = "sk-...."\n\n# Good\nimport os\nAPI_KEY = os.environ["API_KEY"]''',
    "api key": '''import os\nAPI_KEY = os.environ.get("API_KEY")\nif not API_KEY:\n    raise RuntimeError("API_KEY not set")''',
    "sql injection": '''# Bad\nquery = f"SELECT * FROM users WHERE name = '{user}'"\n\n# Good\ncursor.execute("SELECT * FROM users WHERE name = %s", (user,))''',
    "command injection": '''# Bad\nos.system("ls " + user_input)\n\n# Good\nimport subprocess\nsubprocess.run(["ls", user_input], check=True)  # no shell''',
    "eval": '''# Bad\nresult = eval(user_data)\n\n# Good\nimport ast\nresult = ast.literal_eval(user_data)  # literals only''',
    "pickle": '''# Bad\ndata = pickle.loads(untrusted)\n\n# Good\nimport json\ndata = json.loads(untrusted)''',
    "debug mode": '''# Bad\nDEBUG = True\napp.run(debug=True)\n\n# Good\nDEBUG = os.environ.get("DEBUG", "0") == "1"''',
    "path traversal": '''# Bad\nopen("/data/" + filename)\n\n# Good\nfrom pathlib import Path\nbase = Path("/data").resolve()\npath = (base / filename).resolve()\nif not str(path).startswith(str(base)):\n    raise ValueError("invalid path")\nopen(path)''',
    "open redirect": '''# Bad\nreturn redirect(request.args.get("next"))\n\n# Good\nallowed = {"/", "/home", "/dashboard"}\nnxt = request.args.get("next", "/")\nif nxt not in allowed:\n    nxt = "/"\nreturn redirect(nxt)''',
    "xss": '''# Bad\nel.innerHTML = userInput\n\n# Good\nel.textContent = userInput''',
    "weak": '''# Bad\nhashlib.md5(password.encode())\n\n# Good\nimport bcrypt\nbcrypt.hashpw(password.encode(), bcrypt.gensalt())''',
    "content-security-policy": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    "hsts": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "cookie": "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",
    "unpinned": '''# Bad\nrequests\n\n# Good\nrequests==2.32.3''',
    "dockerfile": '''# Bad\nUSER root\n# Good\nUSER nonroot''',
}


def snippet_for(title: str, recommendation: str | None = None) -> Optional[str]:
    t = (title or "").lower()
    for key, snip in SNIPPETS.items():
        if key in t:
            return snip
    return None
