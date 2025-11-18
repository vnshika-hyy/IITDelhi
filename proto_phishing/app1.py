# streamlit_app.py
import streamlit as st
import pandas as pd
import numpy as np
import pickle
import re
from datetime import datetime
try:
    # Python 3.9+ recommended
    from zoneinfo import ZoneInfo
    KOLKATA = ZoneInfo("Asia/Kolkata")
except Exception:
    # fallback - naive local time (still works)
    KOLKATA = None

from io import BytesIO

st.set_page_config(page_title="Phishing URL Detector", layout="wide")

st.title("Phishing URL Detection — Batch CSV + Downloadable Report")
st.markdown(
    """
Upload a CSV with a column named **`url`**. The app will predict each URL as **safe** or **phishing**, 
and let you download an Excel report containing the results and detection timestamp.
"""
)

# -------------------
# Helpers
# -------------------
@st.cache_data(show_spinner=False)
def load_pickle(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def clean_url(u: str) -> str:
    if not isinstance(u, str):
        return ""
    # remove scheme and leading www.
    return re.sub(r"^https?://(www\.)?", "", u.strip())

def predict_urls(urls, vectorizer, model):
    cleaned = [clean_url(u) for u in urls]
    X = vectorizer.transform(cleaned)
    preds = model.predict(X)
    return preds, cleaned

def make_excel_bytes(df: pd.DataFrame, sheet_name: str = "results"):
    buffer = BytesIO()
    with pd.ExcelWriter(buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name=sheet_name)
    buffer.seek(0)
    return buffer.read()

# -------------------
# Load models (if present)
# -------------------
st.sidebar.header("Model & Files")
st.sidebar.markdown("App expects `vectorizer.pkl` and one of `phishing.pkl` or `phishing_mnb.pkl` to be present in working directory.")

model_options = {}
# Attempt to load vectorizer and models gracefully
vec_loaded = False
model_loaded_names = []
try:
    vectorizer = load_pickle("vectorizer.pkl")
    vec_loaded = True
except Exception as e:
    st.sidebar.error("Could not load `vectorizer.pkl` from app folder.")
    st.sidebar.write("Error:", e)
    vectorizer = None

# Try primary model
try:
    model = load_pickle("phishing.pkl")
    model_options["phishing.pkl"] = model
    model_loaded_names.append("phishing.pkl")
except Exception:
    model = None

# Optional alternative model
try:
    m2 = load_pickle("phishing_mnb.pkl")
    model_options["phishing_mnb.pkl"] = m2
    model_loaded_names.append("phishing_mnb.pkl")
except Exception:
    pass

if not model_options:
    st.sidebar.warning("No model found. Upload model files or place them beside this app as `phishing.pkl` or `phishing_mnb.pkl`.")
else:
    st.sidebar.success(f"Loaded model file(s): {', '.join(model_loaded_names)}")

# Let user choose which model to use if multiple available
if model_options:
    model_choice = st.sidebar.selectbox("Choose model to use", options=list(model_options.keys()))
    model = model_options[model_choice]

# -------------------
# File uploader
# -------------------
uploaded_file = st.file_uploader("Upload CSV file (must contain 'url' column)", type=["csv"])

if uploaded_file is None:
    st.info("Upload a CSV to start. Example: a single column `url` or a CSV with multiple columns including `url`.")
    st.stop()

# Read CSV
try:
    df = pd.read_csv(uploaded_file)
except Exception as e:
    st.error(f"Could not read uploaded CSV: {e}")
    st.stop()

if "url" not in df.columns:
    st.warning("Uploaded CSV does not contain a column named 'url'. If the column name is different, rename it to 'url' and re-upload.")
    st.write("Your file columns:", list(df.columns))
    st.stop()

# Preview
st.subheader("Preview of uploaded data")
st.dataframe(df.head(10))

# Options
st.sidebar.header("Options")
use_chunking = st.sidebar.checkbox("Process in chunks (safer for very large files)", value=True)
chunk_size = st.sidebar.number_input("Chunk size", min_value=100, max_value=200000, value=5000, step=100)

# Run prediction
if st.button("Run detection"):
    if not vec_loaded or model is None:
        st.error("Model or vectorizer not loaded. Check logs in sidebar.")
        st.stop()

    urls = df["url"].astype(str).tolist()
    n = len(urls)
    st.info(f"Processing {n} URLs...")

    results = []
    start_time = datetime.now(KOLKATA) if KOLKATA else datetime.now()
    # use a single detection time for the batch (the user asked for time/date of detection)
    detection_dt = start_time
    detection_date = detection_dt.date().isoformat()
    detection_time = detection_dt.time().strftime("%H:%M:%S")
    detection_dt_iso = detection_dt.isoformat()

    progress = st.progress(0)
    try:
        if use_chunking and n > chunk_size:
            for i in range(0, n, chunk_size):
                chunk_urls = urls[i:i+chunk_size]
                preds, cleaned = predict_urls(chunk_urls, vectorizer, model)
                for u,p,c in zip(chunk_urls, preds, cleaned):
                    results.append((u, c, p))
                progress.progress(min(1.0, (i+chunk_size)/n))
        else:
            preds, cleaned = predict_urls(urls, vectorizer, model)
            for u,p,c in zip(urls, preds, cleaned):
                results.append((u, c, p))
            progress.progress(1.0)
    except Exception as e:
        st.error(f"Error during prediction: {e}")
        st.stop()

    # Build DataFrame results
    res_df = pd.DataFrame(results, columns=["url_raw", "url_cleaned", "label"])
    # Map labels to readable
    def human_label(l):
        # common mapping used in your existing flask app: 'bad' => phishing, 'good' => safe
        if str(l).lower() in ("bad", "phishing", "1"):
            return "phishing"
        if str(l).lower() in ("good", "safe", "0"):
            return "safe"
        # fallback
        return str(l)

    res_df["label_readable"] = res_df["label"].apply(human_label)
    res_df["detection_date"] = detection_date
    res_df["detection_time"] = detection_time
    res_df["detection_datetime"] = detection_dt_iso

    # columns for output: url, label, label_readable, date, time
    output_df = res_df[["url_raw", "label", "label_readable", "detection_date", "detection_time", "detection_datetime"]].rename(columns={
        "url_raw": "url",
        "label": "label_internal"
    })

    st.success("Detection finished.")
    # Summary
    st.subheader("Summary")
    counts = output_df["label_readable"].value_counts().to_dict()
    st.write(counts)
    st.dataframe(output_df.head(20))

    # Download buttons
    csv_bytes = output_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download CSV", data=csv_bytes, file_name="phishing_detection_results.csv", mime="text/csv")

    try:
        xlsx_bytes = make_excel_bytes(output_df, sheet_name="results")
        st.download_button("Download Excel (.xlsx)", data=xlsx_bytes, file_name="phishing_detection_results.xlsx", mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    except Exception as e:
        st.warning(f"Could not create Excel file: {e}. You can still download CSV.")

    # Optionally show sample phishing rows
    st.subheader("Sample flagged as phishing")
    st.dataframe(output_df[output_df["label_readable"] == "phishing"].head(10))

    st.info("Report columns: url, label_internal (model raw), label_readable (safe/phishing), detection_date, detection_time, detection_datetime")
