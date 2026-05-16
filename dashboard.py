#!/usr/bin/env python3
"""AI Threat Watch dashboard — single-file Streamlit app.

Run:
    pip install -r requirements-dashboard.txt
    streamlit run dashboard.py

Reads from data/threat_register.sqlite (read-only). No edits to the register.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "data" / "threat_register.sqlite"


@st.cache_data(ttl=60)
def load_data() -> pd.DataFrame:
    if not DB_PATH.exists():
        return pd.DataFrame()
    with sqlite3.connect(DB_PATH) as conn:
        df = pd.read_sql_query("SELECT * FROM threat_register", conn)
    if df.empty:
        return df
    for col in ("collected_at", "published_at", "reviewed_at"):
        if col in df.columns:
            df[col] = pd.to_datetime(df[col], errors="coerce", utc=True)
    return df


def kpi_row(df: pd.DataFrame) -> None:
    total = len(df)
    high = int((df["priority"] == "High").sum()) if "priority" in df.columns else 0
    yes_impact = int((df["company_impact"] == "Yes").sum()) if "company_impact" in df.columns else 0
    in_kev = int(df["in_kev"].sum()) if "in_kev" in df.columns else 0
    pending = int(((df["priority"] == "High") & (df["status"].isin(["New", "Reviewing"]))).sum()) if "priority" in df.columns else 0

    cols = st.columns(5)
    cols[0].metric("Total records", total)
    cols[1].metric("High priority", high)
    cols[2].metric("Company impact: Yes", yes_impact)
    cols[3].metric("KEV-listed", in_kev)
    cols[4].metric("Pending High (New/Reviewing)", pending)


def trend_chart(df: pd.DataFrame, days: int) -> None:
    if df.empty or "collected_at" not in df.columns:
        st.info("No data to chart.")
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    sub = df[df["collected_at"] >= cutoff].copy()
    if sub.empty:
        st.info(f"No records in the last {days} days.")
        return
    sub["date"] = sub["collected_at"].dt.date
    daily = sub.groupby(["date", "priority"]).size().unstack(fill_value=0)
    # Reorder columns for visual consistency
    for col in ("High", "Medium", "Low"):
        if col not in daily.columns:
            daily[col] = 0
    daily = daily[["High", "Medium", "Low"]]
    st.bar_chart(daily, height=320)


def category_table(df: pd.DataFrame) -> None:
    if df.empty or "category" not in df.columns:
        return
    cat = df.groupby("category").size().reset_index(name="count").sort_values("count", ascending=False)
    st.dataframe(cat, use_container_width=True, hide_index=True)


def kev_due_section(df: pd.DataFrame) -> None:
    if df.empty or "in_kev" not in df.columns:
        return
    kev = df[df["in_kev"] == 1].copy()
    if kev.empty:
        st.info("No KEV-listed items.")
        return
    kev["kev_due_date_parsed"] = pd.to_datetime(kev["kev_due_date"], errors="coerce")
    today = pd.Timestamp.now(tz="UTC").normalize()
    kev["days_to_due"] = (kev["kev_due_date_parsed"].dt.tz_localize("UTC", nonexistent="shift_forward") - today).dt.days
    kev = kev.sort_values("days_to_due", na_position="last")
    cols = [
        "threat_id", "kev_due_date", "days_to_due", "cve_ids",
        "priority", "status", "title", "url",
    ]
    cols = [c for c in cols if c in kev.columns]
    st.dataframe(
        kev[cols].rename(columns={"days_to_due": "days_to_due (negative = overdue)"}),
        use_container_width=True,
        hide_index=True,
    )


def filtered_table(df: pd.DataFrame) -> None:
    if df.empty:
        return
    with st.sidebar:
        st.subheader("Filters")
        priorities = st.multiselect(
            "Priority",
            sorted(df["priority"].dropna().unique().tolist()),
            default=["High"],
        )
        impacts = st.multiselect(
            "Company Impact",
            sorted(df["company_impact"].dropna().unique().tolist()),
        )
        statuses = st.multiselect(
            "Status",
            sorted(df["status"].dropna().unique().tolist()),
        )
        kev_only = st.checkbox("KEV-listed only")
        days_back = st.slider("Window (days)", min_value=1, max_value=180, value=30)

    sub = df.copy()
    if priorities:
        sub = sub[sub["priority"].isin(priorities)]
    if impacts:
        sub = sub[sub["company_impact"].isin(impacts)]
    if statuses:
        sub = sub[sub["status"].isin(statuses)]
    if kev_only and "in_kev" in sub.columns:
        sub = sub[sub["in_kev"] == 1]
    cutoff = datetime.now(timezone.utc) - timedelta(days=days_back)
    sub = sub[sub["collected_at"] >= cutoff]

    st.write(f"Matching: **{len(sub)}** records")
    cols = [
        "threat_id", "collected_at", "priority", "severity", "category",
        "company_impact", "affected_asset", "in_kev", "epss_max_score",
        "status", "source", "title",
    ]
    cols = [c for c in cols if c in sub.columns]
    sub = sub.sort_values("collected_at", ascending=False)
    st.dataframe(sub[cols], use_container_width=True, hide_index=True)


def main() -> None:
    st.set_page_config(page_title="AI Threat Watch", layout="wide")
    st.title("AI Threat Watch — Dashboard")
    if not DB_PATH.exists():
        st.error(f"Database not found at {DB_PATH}. Run `python main.py collect` first.")
        return
    df = load_data()
    if df.empty:
        st.warning("No records yet. Run `python main.py collect`.")
        return

    kpi_row(df)
    st.divider()
    st.subheader("Activity (last 30 days)")
    trend_chart(df, days=30)

    col_left, col_right = st.columns([1, 1])
    with col_left:
        st.subheader("By Category")
        category_table(df)
    with col_right:
        st.subheader("KEV-listed items (sorted by due date)")
        kev_due_section(df)

    st.divider()
    st.subheader("Browse records")
    filtered_table(df)


if __name__ == "__main__":
    main()
