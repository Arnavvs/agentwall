from __future__ import annotations

import plotly.graph_objects as go


def vector_bar(events_by_vector: list[dict]) -> go.Figure:
    fig = go.Figure()
    vectors: dict[str, int] = {}
    for e in events_by_vector:
        vectors[e["vector"]] = vectors.get(e["vector"], 0) + e["count"]
    if vectors:
        fig.add_trace(go.Bar(x=list(vectors.keys()), y=list(vectors.values())))
    fig.update_layout(title="Threats by Vector", xaxis_title="Vector", yaxis_title="Count")
    return fig


def severity_donut(events_by_vector: list[dict]) -> go.Figure:
    fig = go.Figure()
    severities: dict[str, int] = {}
    for e in events_by_vector:
        severities[e["severity"]] = severities.get(e["severity"], 0) + e["count"]
    if severities:
        fig.add_trace(
            go.Pie(
                labels=list(severities.keys()),
                values=list(severities.values()),
                hole=0.4,
            )
        )
    fig.update_layout(title="Severity Distribution")
    return fig


def timeline(events: list[dict]) -> go.Figure:
    fig = go.Figure()
    if events:
        timestamps = [e.get("timestamp", "") for e in events]
        scores = [e.get("threat_score", 0) for e in events]
        color_map = {
            "CRITICAL": "red", "HIGH": "orange",
            "MEDIUM": "yellow", "LOW": "blue", "SAFE": "green",
        }
        colors = [
            color_map.get(e.get("severity", "SAFE"), "gray")
            for e in events
        ]
        fig.add_trace(go.Scatter(x=timestamps, y=scores, mode="markers", marker=dict(color=colors)))
    fig.update_layout(title="Threat Timeline", xaxis_title="Time", yaxis_title="Score")
    return fig
