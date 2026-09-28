import io
import json
import pickle
import re
import os
import stat
import tempfile
import zipfile
from pathlib import Path

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
uploaded_imports = {}

CHAT_UI = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Training Agent</title>
  <style>
    :root { color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    body { background:#090909; color:#eee; margin:0; min-height:100vh; display:grid; place-items:center; }
    main { width:min(760px, calc(100% - 32px)); }
    h1 { font-size:16px; font-weight:500; border-bottom:1px solid #333; padding-bottom:16px; }
    .muted { color:#888; font-size:12px; }
    textarea { box-sizing:border-box; width:100%; min-height:110px; background:#111; color:#eee; border:1px solid #444; padding:14px; font:inherit; resize:vertical; }
    button { margin-top:10px; background:#eee; color:#090909; border:0; padding:10px 16px; font:inherit; cursor:pointer; }
    pre { white-space:pre-wrap; overflow:auto; background:#111; border:1px solid #333; padding:14px; min-height:120px; color:#cfcfcf; }
  </style>
</head>
<body>
  <main>
    <h1>aurora@lab:~$ training-agent</h1>
    <p class="muted">Local training interface · intentionally vulnerable ZIP analyzer</p>
    <textarea id="message" placeholder="Ask the agent to analyze a ZIP URL or uploaded archive..."></textarea>
    <input id="archive" type="file" accept=".zip" />
    <button id="send">send</button>
    <pre id="output">Agent output will appear here.</pre>
  </main>
  <script>
    const input = document.querySelector("#message");
    const output = document.querySelector("#output");
    document.querySelector("#send").onclick = async () => {
      output.textContent = "Thinking...";
      try {
        const form = new FormData();
        const archiveInput = document.querySelector("#archive");
        form.append("message", input.value);
        const archive = archiveInput.files[0];
        if (archive) form.append("archive", archive);
        const response = await fetch("/chat", {
          method: "POST",
          body: form
        });
        const body = await response.json().catch(() => ({
          error: `Server returned HTTP ${response.status}`
        }));
        output.textContent = JSON.stringify(body, null, 2);
        archiveInput.value = "";
      } catch (error) {
        output.textContent = JSON.stringify({
          error: "The training agent could not complete the request.",
          details: String(error)
        }, null, 2);
      }
    };
  </script>
</body>
</html>"""


@app.get("/health")
def health():
    return {"status": "ok"}


def analyze_archive_bytes(archive_content, source):
    results = []

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with zipfile.ZipFile(io.BytesIO(archive_content)) as bundle:
            for info in bundle.infolist():
                destination = root / info.filename
                if info.is_dir() or info.filename.endswith("/"):
                    destination.mkdir(parents=True, exist_ok=True)
                    continue

                destination.parent.mkdir(parents=True, exist_ok=True)

                # INTENTIONALLY VULNERABLE: recreates archive symlinks and
                # follows them while reading. This is the behavior under test.
                file_mode = (info.external_attr >> 16) & 0o170000
                if stat.S_ISLNK(file_mode) or info.filename.endswith(".link"):
                    target = bundle.read(info).decode().strip()
                    if info.filename.endswith(".link") and not stat.S_ISLNK(file_mode):
                        destination = destination.with_suffix("")
                    if destination.exists() or destination.is_symlink():
                        destination.unlink()
                    destination.symlink_to(target)
                    continue

                destination.write_bytes(bundle.read(info))

            for path in root.rglob("*"):
                if path.is_file() or path.is_symlink():
                    try:
                        results.append(
                            {
                                "file": str(path.relative_to(root)),
                                "content": path.read_text(errors="replace")[:300],
                            }
                        )
                    except OSError as error:
                        results.append({"file": str(path.relative_to(root)), "error": str(error)})

    return {"files": results, "source": source, "vulnerable": True}


def analyze_archive(archive_url):
    if not archive_url:
        return {"error": "missing url"}

    archive = requests.get(archive_url, timeout=(5, 15))
    archive.raise_for_status()
    return analyze_archive_bytes(archive.content, archive_url)


def analyze_uploaded_import(archive_content):
    """INTENTIONALLY VULNERABLE: loads a user-controlled pickle from a ZIP."""
    thread = Path("/thread")
    thread.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        with zipfile.ZipFile(io.BytesIO(archive_content)) as bundle:
            bundle.extractall(root)
            members = bundle.namelist()

        pickle_files = list(root.rglob("*.pkl"))
        if not pickle_files:
            return {
                "error": "The ZIP did not contain an import schema pickle.",
                "members": members,
                "vulnerable": True,
            }

        # INTENTIONALLY UNSAFE: the training case demonstrates pickle.load().
        with pickle_files[0].open("rb") as handle:
            pickle.load(handle)

        proof = []
        for path in sorted(thread.glob("pickle_*.txt")):
            proof.append(
                {"file": str(path), "content": path.read_text(errors="replace")[:500]}
            )
        return {
            "members": members,
            "pickle_loaded": str(pickle_files[0].relative_to(root)),
            "proof_of_execution": proof,
            "vulnerable": True,
        }


def inspect_uploaded_import(archive_content):
    """Return the trusted-looking CSV without loading the hidden Pickle."""
    with zipfile.ZipFile(io.BytesIO(archive_content)) as bundle:
        members = bundle.namelist()
        csv_members = [name for name in members if name.endswith(".csv")]
        csv_preview = []
        for name in csv_members:
            csv_preview.append(
                {
                    "file": name,
                    "content": bundle.read(name).decode(errors="replace")[:1000],
                }
            )
    return {
        "members": members,
        "csv": csv_preview,
        "pickle_loaded": False,
        "next_step": "Ask the agent to load the ETL schema cache with Python.",
        "vulnerable": True,
    }


@app.get("/")
def index():
    return CHAT_UI


@app.get("/analyze")
def analyze():
    archive_url = request.args.get("url", "")
    if not archive_url:
        return jsonify(error="missing url"), 400
    return jsonify(analyze_archive(archive_url))


@app.post("/chat")
def chat():
    payload = request.get_json(silent=True) or request.form
    message = payload.get("message", "")
    client_key = request.remote_addr or "local-training-user"
    uploaded_archive = request.files.get("archive")
    if uploaded_archive:
        try:
            archive_content = uploaded_archive.read()
            uploaded_imports[client_key] = archive_content
            return jsonify(
                answer="I unpacked the import bundle, listed the files, and processed the contact CSV.",
                details=inspect_uploaded_import(archive_content),
            )
        except (zipfile.BadZipFile, OSError, pickle.UnpicklingError) as error:
            return jsonify(
                answer="The uploaded import bundle could not be processed.",
                error=str(error),
            ), 422

    pickle_request = re.search(
        r"\b(pickle|\.pkl|etl schema|schema cache|load it with python)\b",
        message,
        re.IGNORECASE,
    )
    if pickle_request and client_key in uploaded_imports:
        try:
            archive_content = uploaded_imports.pop(client_key)
            return jsonify(
                answer="I loaded the ETL schema cache and continued the contact import.",
                details=analyze_uploaded_import(archive_content),
            )
        except (zipfile.BadZipFile, OSError, pickle.UnpicklingError) as error:
            return jsonify(
                answer="The ETL schema cache could not be loaded.",
                error=str(error),
            ), 422

    match = re.search(r"https?://[^\s]+", message)
    if not match:
        return jsonify(
            answer="Please provide a ZIP URL for the training analysis.",
            hint="Try http://files:8000/data.zip",
        )

    try:
        return jsonify(
            answer="I analyzed the archive and returned the extracted files.",
            details=analyze_archive(match.group(0).rstrip(".,)")),
        )
    except requests.RequestException as error:
        return jsonify(answer="The archive could not be downloaded.", error=str(error)), 502
    except (zipfile.BadZipFile, OSError, UnicodeDecodeError) as error:
        return jsonify(
            answer="The archive was downloaded but could not be processed.",
            error=str(error),
        ), 422


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
