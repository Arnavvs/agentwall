# AgentWall Architecture

## Pipeline

```
INPUT → Normalizer → Classifiers (parallel) → Threat Scorer → Policy Engine → Action
                                                                    ↓
                                                              Audit (OTel + SQLite + Sentinel)
OUTPUT → Output Validator (leak + secrets + PII) → Action
```

## Layers

1. **Normalizer** — Unicode NFKC, zero-width strip, base64/rot13/hex decoders, JSON/HTML/Markdown flatten
2. **Classifiers** — Prompt Shield (Azure), AI Language (Azure), Rule Engine (local regex + fuzzy)
3. **Threat Scorer** — Noisy-OR aggregation with configurable weights
4. **Policy Engine** — YAML-configured per-agent policies with ALLOW/BLOCK/SANITIZE/REDACT/ESCALATE
5. **Output Validator** — System prompt leak, secret scanner, PII detection
6. **Audit** — OpenTelemetry, SQLite mirror, Sentinel forwarding

## Integration Points

- **AutoGen 0.4** — Instance method patching on `on_messages`
- **AutoGen 0.2** — `register_hook` on `process_last_received_message` / `process_message_before_send`
- **Semantic Kernel** — `@kernel.filter(FilterTypes.PROMPT_RENDERING)` and `FUNCTION_INVOCATION`
