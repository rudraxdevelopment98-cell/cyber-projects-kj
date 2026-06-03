"""
Threat Intelligence Dashboard (Streamlit).

Run locally:
    streamlit run dashboard/app.py

Deploy free on Streamlit Community Cloud by pointing it at this file. The app
reads the scored dataset from ``data/iocs.json`` and falls back to the bundled
``data/demo_iocs.json`` so it renders out-of-the-box with no pipeline run or API
keys required.
"""

import json
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# Make the project root importable so we can reuse the scoring engine.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scoring import score_ioc, classify  # noqa: E402

DATA = ROOT / "data" / "iocs.json"
DEMO = ROOT / "data" / "demo_iocs.json"

SEVERITY_COLORS = {
    "Critical": "#c0392b", "High": "#e67e22",
    "Medium": "#d4ac0d", "Low": "#2980b9",
}


@st.cache_data
def load_iocs():
    """Load scored IOCs, falling back to the demo dataset."""
    path = DATA if DATA.exists() else DEMO
    iocs = json.loads(path.read_text())["iocs"]
    for ioc in iocs:
        ioc.setdefault("risk_score", score_ioc(ioc))
        ioc.setdefault("severity", classify(ioc["risk_score"]))
        ioc["tags_str"] = ", ".join(ioc.get("tags", []))
    return pd.DataFrame(iocs), path.name


def main():
    st.set_page_config(page_title="Threat Intelligence Dashboard",
                       page_icon="🛡️", layout="wide")
    st.title("🛡️ Threat Intelligence Dashboard")
    st.caption("IOC aggregation · enrichment · risk scoring — by Kuldeep J. Jotaniya")

    df, source_file = load_iocs()
    st.info(f"Loaded {len(df)} indicators from `{source_file}`. "
            "Run `python main.py --collect` to refresh from live feeds.")

    # --- Sidebar filters ---
    st.sidebar.header("Filters")
    sev_filter = st.sidebar.multiselect(
        "Severity", sorted(df["severity"].unique()),
        default=sorted(df["severity"].unique()))
    type_filter = st.sidebar.multiselect(
        "IOC type", sorted(df["type"].unique()),
        default=sorted(df["type"].unique()))
    min_score = st.sidebar.slider("Minimum risk score", 1, 10, 1)

    view = df[df["severity"].isin(sev_filter)
              & df["type"].isin(type_filter)
              & (df["risk_score"] >= min_score)]

    # --- KPI row ---
    c1, c2, c3, c4 = st.columns(4)
    counts = Counter(view["severity"])
    c1.metric("Total IOCs", len(view))
    c2.metric("🔴 Critical", counts.get("Critical", 0))
    c3.metric("🟠 High", counts.get("High", 0))
    c4.metric("Avg risk", round(view["risk_score"].mean(), 1) if len(view) else 0)

    # --- Charts ---
    left, right = st.columns(2)
    with left:
        st.subheader("IOC Type Distribution")
        type_counts = view["type"].value_counts().reset_index()
        type_counts.columns = ["type", "count"]
        st.plotly_chart(px.pie(type_counts, names="type", values="count",
                               hole=0.4), use_container_width=True)
    with right:
        st.subheader("Risk Score Distribution")
        st.plotly_chart(px.histogram(view, x="risk_score", color="severity",
                                     nbins=10,
                                     color_discrete_map=SEVERITY_COLORS),
                        use_container_width=True)

    st.subheader("Feed Source Breakdown")
    src = Counter()
    for s in view["source"]:
        for part in str(s).split(", "):
            src[part] += 1
    src_df = pd.DataFrame(src.items(), columns=["source", "count"]).sort_values("count")
    st.plotly_chart(px.bar(src_df, x="count", y="source", orientation="h"),
                    use_container_width=True)

    # --- Manual lookup ---
    st.subheader("🔎 IOC Lookup")
    query = st.text_input("Search the current dataset (IP, domain, URL, hash)")
    if query:
        hits = view[view["ioc"].str.contains(query, case=False, na=False)]
        st.write(f"{len(hits)} match(es)")
        st.dataframe(hits, use_container_width=True)

    # --- Full table ---
    st.subheader("All Indicators")
    cols = ["risk_score", "severity", "type", "ioc", "source",
            "vt_detection_ratio", "abuseipdb_score", "first_seen", "tags_str"]
    show = [c for c in cols if c in view.columns]
    st.dataframe(view[show].sort_values("risk_score", ascending=False),
                 use_container_width=True, height=420)

    st.download_button("⬇️ Export as CSV",
                       view.to_csv(index=False).encode("utf-8"),
                       "iocs_export.csv", "text/csv")


if __name__ == "__main__":
    main()
