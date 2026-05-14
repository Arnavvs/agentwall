from __future__ import annotations

import asyncio

import streamlit as st

from agentwall.dashboard.charts import severity_donut, timeline, vector_bar
from agentwall.dashboard.repo import EventsRepository

st.set_page_config(page_title="AgentWall", layout="wide", page_icon="\U0001f6e1\ufe0f")

st.title("\U0001f6e1\ufe0f AgentWall — Live Threat Dashboard")

db_path = st.sidebar.text_input("Database Path", "./agentwall_events.db")
repo = EventsRepository(db_path)


@st.cache_data(ttl=2)
def fetch_stats(db: str) -> dict:
    r = EventsRepository(db)
    return asyncio.run(r.get_stats())


@st.cache_data(ttl=2)
def fetch_events(db: str, limit: int) -> list:
    r = EventsRepository(db)
    return asyncio.run(r.recent_events(limit))


@st.cache_data(ttl=2)
def fetch_by_vector(db: str) -> list:
    r = EventsRepository(db)
    return asyncio.run(r.events_by_vector())


stats = fetch_stats(db_path)
col1, col2, col3, col4 = st.columns(4)
col1.metric("Blocked", stats.get("blocked", 0))
col2.metric("Sanitized", stats.get("sanitized", 0))
col3.metric("Escalated", stats.get("escalated", 0))
col4.metric("Allowed", stats.get("allowed", 0))

col_a, col_b = st.columns(2)
by_vector = fetch_by_vector(db_path)
col_a.plotly_chart(vector_bar(by_vector), use_container_width=True)
col_b.plotly_chart(severity_donut(by_vector), use_container_width=True)

events = fetch_events(db_path, 200)
st.plotly_chart(timeline(events), use_container_width=True)

st.subheader("Live Event Feed")
for ev in events[:50]:
    severity_color = {
        "CRITICAL": "\U0001f534",
        "HIGH": "\U0001f7e0",
        "MEDIUM": "\U0001f7e1",
        "LOW": "\U0001f535",
    }.get(ev.get("severity", ""), "\u26aa")
    label = (
        f"{severity_color} {ev.get('timestamp', '')} "
        f"\u2022 {ev.get('vector', '')} \u2022 "
        f"{ev.get('agent_id', '')} \u2022 {ev.get('action', '')}"
    )
    with st.expander(label):
        st.json(ev)

st.markdown('<meta http-equiv="refresh" content="2">', unsafe_allow_html=True)
