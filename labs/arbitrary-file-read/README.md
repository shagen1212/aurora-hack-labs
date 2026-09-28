# Arbitrary file read: ZIP symbolic links and hidden Pickle

This lab models a trusted chat tool that downloads a ZIP and returns the
contents of every extracted file. The vulnerable extractor recreates symbolic
links before reading them. The same chat also accepts an import ZIP containing
a legitimate CSV and a hidden Pickle payload, demonstrating unsafe
deserialization through the agent's execution path.

## Run

```bash
docker compose -f labs/arbitrary-file-read/docker-compose.yml up --build
```

In another terminal:

```bash
open http://localhost:8081
```

Use the chat input and ask for the URL-based case:

```text
Analyze this ZIP: http://files:8000/data.zip
```

The response contains the training container's fake files. The `files`
hostname is available only on the Compose network. The raw endpoint remains
available for debugging:

```bash
curl 'http://localhost:8081/analyze?url=http://files:8000/data.zip'
```

For the second case, create an authorized training ZIP with a CSV and a
controlled proof-of-execution `.pkl`, then select it in the upload control.
The chat unpacks the bundle, loads the Pickle and returns proof files created
under `/thread/`. This is intentionally unsafe and must only be run in the
isolated lab container.

## Lesson

Reject symlinks, hardlinks, device files, absolute paths and traversal before
extraction. Never deserialize user-controlled Pickle; use a safe,
schema-validated format instead. Extract in a disposable, least-privileged
sandbox and never give the model direct filesystem or shell access.

## Stop

```bash
docker compose -f labs/arbitrary-file-read/docker-compose.yml down
```
