import pytest


@pytest.fixture
def sample_policy_path(tmp_path):
    policy = tmp_path / "test_policy.yaml"
    policy.write_text("""
apiVersion: agentwall.dev/v1
kind: AgentPolicy
metadata:
  name: test
  description: "Test policy"
spec:
  agents:
    "*":
      vectors:
        prompt_injection:
          enabled: true
          action: BLOCK
          classifiers: [rule_engine]
          score_threshold: 0.5
        indirect_injection:
          enabled: true
          action: BLOCK
          classifiers: [rule_engine]
        obfuscation:
          enabled: true
          action: SANITIZE
          decoders: [base64, rot13, hex, unicode_normalize]
        jailbreak:
          enabled: true
          action: BLOCK
          score_threshold: 0.5
        prompt_leaking:
          enabled: true
          action: BLOCK
          detection_modes: [inbound_intent, outbound_overlap]
        mcp_poisoning:
          enabled: true
          action: BLOCK
          scan_tools_list: true
          scan_tool_responses: true
          forbidden_keys: ["SYSTEM NOTE", "CRITICAL OVERRIDE"]
          forbidden_patterns: ["<IMPORTANT>", "<SYSTEM>"]
        tool_scope:
          enabled: true
          action: BLOCK
          mode: allowlist
          tools: []
      output_validation:
        enabled: true
        action: REDACT
        detectors:
          system_prompt_leak:
            enabled: true
            similarity_threshold: 80
          secret_scanner:
            enabled: true
            patterns: [all]
            entropy_check: true
            entropy_threshold: 4.5
          pii:
            enabled: true
            categories: [Email, PhoneNumber]
            confidence_threshold: 0.85
      escalation:
        sentinel_min_severity: HIGH
        alert_threshold:
          count: 3
          window_seconds: 60
      audit:
        log_all_events: true
        log_payloads: false
        retention_days: 30
  agent_overrides: {}
""")
    return policy
