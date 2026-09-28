import os
import re
import tempfile
from pathlib import Path

import pandas as pd
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)
pending_artifacts = {}
pending_csv_urls = {}

CHAT_UI = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RCE Training Agent</title>
  <style>
    :root { color-scheme: dark; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
    body { background:#090909; color:#eee; margin:0; min-height:100vh; display:grid; place-items:center; }
    main { width:min(760px, calc(100% - 32px)); }
    h1 { font-size:16px; font-weight:500; border-bottom:1px solid #333; padding-bottom:16px; }
    .muted { color:#888; font-size:12px; }
    textarea { box-sizing:border-box; width:100%; min-height:110px; background:#111; color:#eee; border:1px solid #444; padding:14px; font:inherit; resize:vertical; }
    input { display:block; margin-top:10px; color:#aaa; font:inherit; font-size:12px; }
    button { margin-top:10px; background:#eee; color:#090909; border:0; padding:10px 16px; font:inherit; cursor:pointer; }
    pre { white-space:pre-wrap; overflow:auto; background:#111; border:1px solid #333; padding:14px; min-height:120px; color:#cfcfcf; }
  </style>
</head>
<body>
  <main>
    <h1>aurora@lab:~$ rce-training-agent</h1>
    <p class="muted">Local training interface · intentionally vulnerable RCE workflows</p>
    <textarea id="message" placeholder="Ask the agent to analyze a CSV/model URL or run an artifact..."></textarea>
    <input id="artifact" type="file" accept=".py,.artifact,.txt" />
    <button id="send">send</button>
    <pre id="output">Agent output will appear here.</pre>
  </main>
  <script>
    const input = document.querySelector("#message");
    const artifactInput = document.querySelector("#artifact");
    const output = document.querySelector("#output");
    document.querySelector("#send").onclick = async () => {
      output.textContent = "Thinking...";
      try {
        const form = new FormData();
        form.append("message", input.value);
        if (artifactInput.files[0]) form.append("artifact", artifactInput.files[0]);
        const response = await fetch("/chat", {method: "POST", body: form});
        const body = await response.json().catch(() => ({error: `Server returned HTTP ${response.status}`}));
        output.textContent = JSON.stringify(body, null, 2);
        artifactInput.value = "";
      } catch (error) {
        output.textContent = JSON.stringify({error: String(error)}, null, 2);
      }
    };
  </script>
</body>
</html>"""


@app.get("/health")
def health():
    return {"status": "ok"}


def analyze_remote(csv_url, model_url=None):
    metrics = pd.read_csv(csv_url)
    filtered = metrics.query("value > 100")
    result = {"rows": filtered.to_dict(orient="records"), "csv_url": csv_url}
    if model_url:
        # INTENTIONALLY VULNERABLE: remote pickle data is deserialized.
        model = pd.read_pickle(model_url)
        result.update(
            model_url=model_url,
            raw_model_value=str(model),
            vulnerable=True,
        )
    else:
        result["next_step"] = "Ask the agent to enrich the query with the predictive model."
    return result


def execute_artifact(artifact_content, filename):
    """INTENTIONALLY VULNERABLE: executes uploaded Python with full builtins."""
    rows = []

    def save_table(table, title):
        rows.extend(
            {"table": title, **record}
            for record in table.to_dict(orient="records")
        )

    with tempfile.TemporaryDirectory() as directory:
        namespace = {
            "__name__": "__artifact__",
            "__file__": str(Path(directory) / filename),
            "save_table": save_table,
        }
        # The complete builtins remain available on purpose for this lab.
        exec(artifact_content.decode("utf-8"), namespace, namespace)

    return {
        "artifact": filename,
        "output_table": rows,
        "cwd": os.getcwd(),
        "vulnerable": True,
    }


@app.get("/analyze")
def analyze():
    csv_url = request.args.get("csv_url", "")
    model_url = request.args.get("model_url", "")
    if not csv_url or not model_url:
        return jsonify(error="csv_url and model_url are required"), 400

    return jsonify(analyze_remote(csv_url, model_url))


@app.get("/")
def index():
    return CHAT_UI


@app.post("/chat")
def chat():
    message = (request.form.get("message") or "").strip()
    client_key = request.remote_addr or "local-training-user"
    artifact = request.files.get("artifact")

    if artifact:
        pending_artifacts[client_key] = (artifact.read(), artifact.filename or "artifact.py")
        return jsonify(
            answer="The Python artifact was uploaded and attached to the analysis context.",
            details={
                "artifact": artifact.filename,
                "artifact_type": "CODE",
                "executed": False,
                "next_step": "Ask the agent to run the attached artifact and show the output table.",
            },
        )

    if client_key in pending_artifacts and re.search(
        r"\b(run|execute|attached|artifact|recon)\b", message, re.IGNORECASE
    ):
        content, filename = pending_artifacts.pop(client_key)
        try:
            return jsonify(
                answer="I ran the attached Python artifact and returned the output table.",
                details=execute_artifact(content, filename),
            )
        except Exception as error:
            return jsonify(answer="The Python artifact failed during execution.", error=str(error)), 422

    urls = re.findall(r"https?://[^\s]+", message)
    urls = [url.rstrip(".,)'\"") for url in urls]
    csv_url = next((url for url in urls if ".csv" in url), None)
    model_url = next((url for url in urls if ".pkl" in url), None)
    if csv_url:
        pending_csv_urls[client_key] = csv_url
    elif model_url:
        csv_url = pending_csv_urls.get(client_key)
    if csv_url:
        try:
            details = analyze_remote(csv_url, model_url)
            if model_url:
                pending_csv_urls.pop(client_key, None)
            return jsonify(
                answer=(
                    "I analyzed the CSV and enriched the query with the predictive model."
                    if model_url
                    else "I analyzed the CSV and filtered values greater than 100."
                ),
                details=details,
            )
        except (requests.RequestException, ValueError, OSError) as error:
            return jsonify(answer="The remote analysis failed.", error=str(error)), 502

    return jsonify(
        answer="Provide a CSV/model URL or upload a Python artifact.",
        hint="Try http://files:8000/metrics.csv and then the model URL.",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
