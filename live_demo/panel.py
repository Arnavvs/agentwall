from __future__ import annotations

from typing import Any

import streamlit as st

HEADER_CONFIGS = {
    "unprotected": {
        "emoji": "⚠️",
        "title": "NO PROTECTION",
        "subtitle": "Raw agent · zero inspection",
        "accent": "#EF4444",
        "header_bg": "linear-gradient(135deg,#7F1D1D,#991B1B)",
    },
    "agt": {
        "emoji": "⚡",
        "title": "AGT ONLY",
        "subtitle": "microsoft/agent-governance-toolkit · action layer only",
        "accent": "#F59E0B",
        "header_bg": "linear-gradient(135deg,#78350F,#92400E)",
    },
    "agentwall": {
        "emoji": "🛡️",
        "title": "AGENTWALL",
        "subtitle": "Content layer · rule engine + MCP scanner",
        "accent": "#22C55E",
        "header_bg": "linear-gradient(135deg,#14532D,#166534)",
    },
}


# ── Message HTML builders (return strings, not st.markdown calls) ─────────────

def _msg_user(text: str) -> str:
    return f"""
    <div style="background:#1E3A5F;border-radius:8px;padding:10px 13px;margin:7px 0;">
        <div style="color:#60A5FA;font-size:10px;font-weight:700;letter-spacing:.8px;
                    text-transform:uppercase;margin-bottom:4px;">YOU</div>
        <div style="color:#E2E8F0;font-size:13px;">{text}</div>
    </div>"""


def _msg_agent(text: str) -> str:
    return f"""
    <div style="background:#111827;border-radius:8px;padding:10px 13px;margin:7px 0;">
        <div style="color:#94A3B8;font-size:10px;font-weight:700;letter-spacing:.8px;
                    text-transform:uppercase;margin-bottom:4px;">AGENT</div>
        <div style="color:#CBD5E1;font-size:13px;white-space:pre-wrap;">{text}</div>
    </div>"""


def _msg_blocked(text: str, severity: str = "", detectors: list[str] | None = None) -> str:
    sev_html = ""
    if severity:
        colors = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#D97706", "LOW": "#65A30D"}
        c = colors.get(severity.upper(), "#64748B")
        sev_html = (
            f'<span style="background:{c};color:#fff;font-size:10px;font-weight:700;'
            f'padding:2px 7px;border-radius:4px;letter-spacing:.5px;">{severity}</span>'
        )

    det_html = ""
    if detectors:
        rows = "".join(
            f'<div style="font-family:monospace;font-size:11px;color:#FCA5A5;padding:1px 0;">↳ {d}</div>'
            for d in detectors
        )
        det_html = f'<div style="margin-top:7px;">{rows}</div>'

    return f"""
    <div style="background:#1C0A0A;border-left:3px solid #EF4444;
                border-radius:0 8px 8px 0;padding:10px 13px;margin:7px 0;">
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px;">
            <span style="color:#EF4444;font-size:13px;font-weight:800;">🔴 BLOCKED</span>
            {sev_html}
        </div>
        {det_html}
        <div style="color:#FCA5A5;font-size:11px;margin-top:6px;opacity:.85;">{text}</div>
    </div>"""


def _msg_allowed(text: str) -> str:
    return f"""
    <div style="background:#052E16;border-left:3px solid #22C55E;
                border-radius:0 8px 8px 0;padding:10px 13px;margin:7px 0;">
        <div style="color:#22C55E;font-weight:800;font-size:13px;margin-bottom:4px;">🟢 ALLOWED</div>
        <div style="color:#86EFAC;font-size:11px;">{text}</div>
    </div>"""


def _msg_agt_miss(text: str) -> str:
    return f"""
    <div style="background:#1C1207;border-left:3px solid #F59E0B;
                border-radius:0 8px 8px 0;padding:10px 13px;margin:7px 0;">
        <div style="color:#F59E0B;font-weight:800;font-size:13px;margin-bottom:6px;">⚠️ ATTACK LANDED</div>
        <div style="color:#FDE68A;font-size:12px;white-space:pre-wrap;margin-bottom:10px;">{text}</div>
        <div style="background:#292524;border:1px solid #44403C;border-radius:6px;
                    padding:8px 11px;font-size:11px;color:#FCD34D;">
            ℹ AGT does not inspect message content.<br>
            From AGT README: <em style="color:#FDE68A;">"This is not a prompt guardrail."</em>
        </div>
    </div>"""


def _msg_mcp(panel_type: str, mcp_data: dict[str, Any] | None = None) -> str:
    if panel_type == "unprotected":
        return """
        <div style="background:#1C0A0A;border-left:3px solid #EF4444;
                    border-radius:0 8px 8px 0;padding:10px 13px;margin:7px 0;">
            <div style="color:#EF4444;font-weight:800;margin-bottom:8px;">🔴 EXFILTRATED</div>
            <div style="font-family:monospace;font-size:11px;color:#FCA5A5;line-height:1.8;">
                Agent reads tools/list including hidden &lt;IMPORTANT&gt; block<br>
                Calls: search_web(sidenote="OPENAI_KEY=sk-abc...")<br>
                <span style="color:#EF4444;font-weight:700;">→ .env contents leaked to attacker ✗</span>
            </div>
        </div>"""

    elif panel_type == "agt":
        return """
        <div style="background:#1C1207;border-left:3px solid #F59E0B;
                    border-radius:0 8px 8px 0;padding:10px 13px;margin:7px 0;">
            <div style="color:#F59E0B;font-weight:800;margin-bottom:8px;">⚠️ ATTACK LANDED</div>
            <div style="font-family:monospace;font-size:11px;color:#FDE68A;line-height:1.8;">
                AGT checks: is 'search_web' in forbidden list? → No<br>
                AGT never reads tool descriptions or metadata<br>
                &lt;IMPORTANT&gt; block invisible to AGT<br>
                <span style="color:#F59E0B;font-weight:700;">→ Exfiltration succeeds ✗</span>
            </div>
            <div style="background:#292524;border:1px solid #44403C;border-radius:6px;
                        padding:8px 11px;margin-top:10px;font-size:11px;color:#FCD34D;">
                ℹ AGT governs tool <em>names</em>, not tool <em>descriptions</em>.<br>
                From AGT README: <em>"This is not a prompt guardrail."</em>
            </div>
        </div>"""

    elif panel_type == "agentwall":
        if mcp_data and mcp_data.get("findings"):
            rows = "".join(
                f'<div style="font-family:monospace;font-size:11px;color:#86EFAC;padding:2px 0;">'
                f'{f["field_path"]}<br>'
                f'<span style="color:#4ADE80;">  matched: <em>"{f["matched_text"]}"</em> → SUSPICIOUS</span>'
                f'</div>'
                for f in mcp_data["findings"]
            )
            return f"""
            <div style="background:#052E16;border-left:3px solid #22C55E;
                        border-radius:0 8px 8px 0;padding:10px 13px;margin:7px 0;">
                <div style="color:#22C55E;font-weight:800;margin-bottom:8px;">🛡️ BLOCKED — MCP SCANNER</div>
                <div style="color:#86EFAC;font-size:11px;margin-bottom:8px;">Scanned tools/list at connect time:</div>
                {rows}
                <div style="margin-top:10px;font-size:11px;color:#4ADE80;font-weight:700;">
                    → Tool never registered in agent context.<br>
                    → Agent never sees poisoned description. ✓
                </div>
            </div>"""
        else:
            return _msg_allowed("MCP tools scanned — no poisoning detected.")

    return ""


# ── Main render function ──────────────────────────────────────────────────────

def render_panel(
    panel_type: str,
    history: list[dict[str, Any]],
    key_suffix: str = "",
) -> None:
    cfg = HEADER_CONFIGS[panel_type]

    # Build ALL panel HTML as one string — critical so divs close properly
    parts: list[str] = []

    # Header
    parts.append(f"""
    <div style="
        background:{cfg['header_bg']};
        border-radius:10px 10px 0 0;
        padding:12px 16px;
        border-bottom:2px solid {cfg['accent']};
    ">
        <div style="display:flex;align-items:center;gap:8px;">
            <span style="font-size:18px;">{cfg['emoji']}</span>
            <div>
                <div style="color:#fff;font-weight:800;font-size:13px;
                            letter-spacing:1px;text-transform:uppercase;">{cfg['title']}</div>
                <div style="color:rgba(255,255,255,.6);font-size:10px;margin-top:2px;">
                    {cfg['subtitle']}</div>
            </div>
        </div>
    </div>""")

    # Message area
    parts.append(f"""
    <div style="
        border:1px solid {cfg['accent']}33;
        border-top:none;
        border-radius:0 0 10px 10px;
        padding:8px 8px 12px 8px;
        min-height:300px;
        background:#080E1A;
        overflow-y:auto;
    ">""")

    if not history:
        parts.append(
            '<div style="text-align:center;color:#1E293B;font-size:12px;'
            'padding:50px 0;font-style:italic;">No messages yet</div>'
        )
    else:
        for entry in history:
            role = entry.get("role", "")
            if role == "user":
                parts.append(_msg_user(entry.get("content", "")))
            elif role == "blocked":
                parts.append(_msg_blocked(
                    entry.get("content", ""),
                    severity=entry.get("severity", ""),
                    detectors=entry.get("detectors"),
                ))
            elif role == "allowed":
                parts.append(_msg_allowed(entry.get("content", "")))
            elif role == "agt_miss":
                parts.append(_msg_agt_miss(entry.get("content", "")))
            elif role == "mcp_display":
                parts.append(_msg_mcp(panel_type, entry.get("mcp_data")))
            else:
                parts.append(_msg_agent(entry.get("content", "")))

    parts.append("</div>")  # close message area

    # Render entire panel as ONE st.markdown call — divs close correctly
    st.markdown("".join(parts), unsafe_allow_html=True)
