# AgentWall

> **Security middleware for AI agents — one line of code.**
>
> Microsoft Build AI Hackathon 2026 Submission

AgentWall is a Python middleware that wraps any AutoGen or Semantic Kernel agent
and enforces a multi-layer security policy across 10 known prompt-hacking attack
vectors via a single line of code.

## Quick Start

```python
import agentwall

protected_agent = agentwall.wrap(agent, policy="strict")
```

```bash
pip install agentwall
```

## What It Protects Against

| Vector | Detection Method |
|---|---|
| Direct prompt injection | Prompt Shield (Azure) + rule engine |
| Indirect/embedded injection | Prompt Shield document mode |
| Obfuscation (base64, rot13, unicode) | Normalizer + re-classify |
| Jailbreak / roleplay | Rule engine (regex + fuzzy) |
| Prompt leaking | Output validator (leak detector) |
| MCP poisoning | Metadata scanner + response validator |
| Tool scope violation | Allowlist + param constraints |
| Secret / API key leaks | Regex + entropy scanner |
| PII exposure | Azure AI Language PII detection |
| Context manipulation | Separator flush detection |

## Architecture

```
INPUT → [Normalizer] → [Classifiers: Prompt Shield + AI Language + Rule Engine]
                                                    ↓
                                           [Threat Scorer: noisy-OR]
                                                    ↓
                                           [Policy Engine: YAML]
                                                    ↓
                                      ALLOW / BLOCK / SANITIZE / REDACT
                                                    ↓
                                    [Audit: OpenTelemetry + SQLite + Sentinel]
```

## Microsoft Stack Mapping

| Azure Service | Role |
|---|---|
| Azure AI Content Safety | Prompt Shield (direct + indirect injection) |
| Azure AI Language | PII detection, intent classification |
| Azure Key Vault | Secret storage (managed identity) |
| Azure Monitor / App Insights | Telemetry via OpenTelemetry |
| Azure Sentinel | HIGH/CRITICAL event forwarding |
| Azure Container Apps | Live deployment |

## Setup

```bash
# Install
pip install agentwall[all]

# Set Azure credentials (optional — rule engine works without)
export AGENTWALL_CS_ENDPOINT="https://<endpoint>.cognitiveservices.azure.com/"
export AGENTWALL_AL_ENDPOINT="https://<endpoint>.cognitiveservices.azure.com/"
```

## Policies

Three built-in policies:

- **`strict`** — Block everything suspicious (default)
- **`moderate`** — Block CRITICAL/HIGH, sanitize MEDIUM
- **`permissive`** — Log everything, block only CRITICAL

```python
agentwall.wrap(agent, policy="strict")       # built-in
agentwall.wrap(agent, policy="./my_policy.yaml")  # custom
```

## Running the Demo

```bash
python demo/protected.py
```

## Running the Dashboard

```bash
pip install streamlit plotly pandas
agentwall-dashboard --db ./agentwall_events.db
```

## Running Tests

```bash
pytest -q
```

## Real CVEs Addressed

- **CVE-2025-54136** (MCPoison) — Malicious MCP server tool descriptions
- **CVE-2025-54135** (CurXecute) — Cursor MCP code execution via tool injection
- **Invariant Labs TPA** (April 2025) — Hidden instructions in tool descriptions

## AI Tools Disclosure

This project was developed with assistance from GitHub Copilot and OpenCode/Codex.
All architecture decisions, code reviews, and final implementations were made by the author.
