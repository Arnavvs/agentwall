# Policy Reference

## Built-in Policies

| Policy | Behavior |
|---|---|
| `strict` | Block on any suspicious activity. Safest default. |
| `moderate` | Block CRITICAL/HIGH, sanitize MEDIUM, allow LOW with logging. |
| `permissive` | Log everything, block only CRITICAL. |

## YAML Schema

```yaml
apiVersion: agentwall.dev/v1
kind: AgentPolicy
metadata:
  name: my-policy
  description: "Custom policy"
spec:
  agents:
    "*":  # wildcard default
      vectors:
        prompt_injection:
          enabled: true
          action: BLOCK        # ALLOW | BLOCK | SANITIZE | REDACT | ESCALATE
          classifiers: [prompt_shield, rule_engine]
          score_threshold: 0.6
        # ... other vectors
      output_validation:
        enabled: true
        action: REDACT
      escalation:
        sentinel_min_severity: HIGH
      audit:
        log_all_events: true
        log_payloads: false
  agent_overrides:
    research-agent:
      vectors:
        tool_scope:
          tools: [web_search, read_file]
```

## Actions

| Action | When to use |
|---|---|
| `ALLOW` | No threat detected, or below threshold |
| `BLOCK` | Clear threat — reject the input/output entirely |
| `SANITIZE` | Decode obfuscation and re-check |
| `REDACT` | Remove sensitive portions (secrets, PII) but pass through |
| `ESCALATE` | Forward to security team / Sentinel |

## Environment Variables

| Variable | Purpose |
|---|---|
| `AGENTWALL_CS_ENDPOINT` | Azure Content Safety endpoint |
| `AGENTWALL_CS_KEY` | Content Safety API key |
| `AGENTWALL_AL_ENDPOINT` | Azure AI Language endpoint |
| `AGENTWALL_AL_KEY` | AI Language API key |
