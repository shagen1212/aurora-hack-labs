import json
import re
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

DATABASE = "/tmp/training.db"
CHAT_UI = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RAG SQLi Training Agent</title>
  <style>
    :root { color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    body { background:#090909; color:#eee; margin:0; min-height:100vh; display:grid; place-items:center; }
    main { width:min(760px, calc(100% - 32px)); }
    h1 { font-size:16px; font-weight:500; border-bottom:1px solid #333; padding-bottom:16px; }
    .muted { color:#888; font-size:12px; }
    textarea { box-sizing:border-box; width:100%; min-height:130px; background:#111; color:#eee; border:1px solid #444; padding:14px; font:inherit; resize:vertical; }
    button { margin-top:10px; background:#eee; color:#090909; border:0; padding:10px 16px; font:inherit; cursor:pointer; }
    pre { white-space:pre-wrap; overflow:auto; background:#111; border:1px solid #333; padding:14px; min-height:160px; color:#cfcfcf; }
  </style>
</head>
<body>
  <main>
    <h1>aurora@lab:~$ rag-training-agent</h1>
    <p class="muted">Local training interface · intentionally vulnerable RAG debug response</p>
    <textarea id="message" placeholder="Ask the RAG assistant about assets..."></textarea>
    <button id="send">send</button>
    <pre id="output">Agent output will appear here.</pre>
  </main>
  <script>
    const input = document.querySelector("#message");
    const output = document.querySelector("#output");
    document.querySelector("#send").onclick = async () => {
      output.textContent = "Thinking...";
      try {
        const response = await fetch("/chat", {
          method: "POST",
          headers: {"content-type": "application/json"},
          body: JSON.stringify({message: input.value})
        });
        const body = await response.json();
        const visible = {
          answer: body.answer,
          results: body.results || [],
          tenant_scope: body.tenant_scope
        };
        output.textContent = JSON.stringify(visible, null, 2);
      } catch (error) {
        output.textContent = JSON.stringify({error: String(error)}, null, 2);
      }
    };
  </script>
</body>
</html>"""


def connection():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def initialize():
    db = connection()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS tvw_tenants (id INTEGER, name TEXT);
        CREATE TABLE IF NOT EXISTS tvw_users (id INTEGER, tenant_id INTEGER, email TEXT, password TEXT);
        CREATE TABLE IF NOT EXISTS tvw_dev_tokens (id INTEGER, tenant_id INTEGER, token TEXT);
        CREATE TABLE IF NOT EXISTS assets (id INTEGER, tenant_id INTEGER, city TEXT, name TEXT);
        DELETE FROM tvw_tenants;
        DELETE FROM tvw_users;
        DELETE FROM tvw_dev_tokens;
        DELETE FROM assets;
        INSERT INTO tvw_tenants VALUES
          (4, 'Sanford Training'), (9, 'Other Training');
        INSERT INTO tvw_users VALUES
          (1, 4, 'student@example.test', 'training-password-4'),
          (2, 9, 'other@example.test', 'training-password-9');
        INSERT INTO tvw_dev_tokens VALUES
          (1, 4, 'training-token-4'),
          (2, 9, 'training-token-9');
        INSERT INTO assets VALUES
          (1, 4, 'Sanford', 'training-laptop'),
          (2, 9, 'Other City', 'other-tenant-asset');
        """
    )
    db.commit()
    db.close()


def handle_chat(message):
    db = connection()
    debug_requested = bool(re.search(r"--\s*debug\b", message, re.IGNORECASE))
    generated_query = (
        "SELECT id, name FROM assets WHERE tenant_id = 4 "
        f"AND city = '{message.split(' in ')[-1].split(',')[0]}'"
    )

    # INTENTIONALLY VULNERABLE: a debug-like branch accepts a subquery-shaped
    # instruction and exposes its result in the response body.
    match = re.search(r"also show \((SELECT .+?)\)\s*--", message, re.IGNORECASE)
    if match:
        generated_query += f"; {match.group(1)}"
        subquery = match.group(1).lower()
        if "information_schema.tables" in subquery:
            rows = [{"table_name": name} for name in ["tvw_tenants", "tvw_users", "tvw_dev_tokens", "assets"]]
        elif "information_schema.columns" in subquery:
            rows = [{"column_name": name} for name in ["id", "tenant_id", "email", "password"]]
        elif "tvw_dev_tokens" in subquery:
            rows = [dict(row) for row in db.execute("SELECT tenant_id, token FROM tvw_dev_tokens").fetchall()]
        elif "password" in subquery:
            rows = [dict(row) for row in db.execute("SELECT id, email, password FROM tvw_users").fetchall()]
        elif "tvw_users" in subquery:
            rows = [dict(row) for row in db.execute("SELECT tenant_id, email FROM tvw_users").fetchall()]
        elif "tvw_tenants" in subquery:
            rows = [dict(row) for row in db.execute("SELECT id, name FROM tvw_tenants").fetchall()]
        else:
            rows = [{"training_result": "controlled SQLi branch reached"}]
    else:
        rows = [
            dict(row)
            for row in db.execute(
                "SELECT id, name FROM assets WHERE tenant_id = 4 AND city = ?",
                ("Sanford",),
            ).fetchall()
        ]

    db.close()
    response = {
        "answer": "Training assistant response",
        "results": rows if not match else [],
        "tenant_scope": 4,
        "vulnerable": True,
    }
    if debug_requested:
        response["debug"] = {"generated_query": generated_query, "rows": rows}
    return response


initialize()


class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload, status=200):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self.send_json({"status": "ok"})
        elif path == "/":
            body = CHAT_UI.encode()
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_json({"error": "use POST /chat"}, 405)

    def do_POST(self):
        if urlparse(self.path).path != "/chat":
            self.send_json({"error": "not found"}, 404)
            return
        length = int(self.headers.get("content-length", "0"))
        payload = json.loads(self.rfile.read(length))
        self.send_json(handle_chat(payload.get("message", "")))


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
