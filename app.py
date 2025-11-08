import streamlit as st
import pandas as pd

st.set_page_config(page_title="Suspicious Login Detector", layout="wide")

st.title("🔐 Suspicious Login Activity Detector")
st.write("Upload a login CSV file (columns: username,timestamp,ip,device,status) and the app will flag suspicious events.")

uploaded_file = st.file_uploader("Choose CSV file", type=["csv"])

FAILED_THRESHOLD = st.sidebar.number_input("Failed attempts threshold", min_value=1, max_value=10, value=3, step=1)
ODD_HOUR_START = st.sidebar.number_input("Odd hour start (inclusive)", min_value=0, max_value=23, value=0)
ODD_HOUR_END = st.sidebar.number_input("Odd hour end (exclusive)", min_value=1, max_value=24, value=5)
INCLUDE_23_AS_ODD = st.sidebar.checkbox("Include hour 23 as odd", value=True)

def analyze_df(df):
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour

    failed_counts = df[df['status'].str.lower() == 'failed'].groupby('username').size()
    suspicious_failed = failed_counts[failed_counts >= FAILED_THRESHOLD]

    if INCLUDE_23_AS_ODD:
        odd_mask = (df['hour'] < ODD_HOUR_END) | (df['hour'] >= 23)
    else:
        odd_mask = (df['hour'] < ODD_HOUR_END)
    odd_rows = df[odd_mask].copy()

    ip_nunique = df.groupby('username')['ip'].nunique()
    ip_change_users = ip_nunique[ip_nunique > 1]

    device_nunique = df.groupby('username')['device'].nunique()
    device_change_users = device_nunique[device_nunique > 1]

    rows = []
    for user, cnt in suspicious_failed.items():
        rows.append({"username": user, "issue": f"Multiple failed attempts ({cnt})"})
    for user, cnt in ip_change_users.items():
        rows.append({"username": user, "issue": f"Multiple IPs used ({cnt})"})
    for user, cnt in device_change_users.items():
        rows.append({"username": user, "issue": f"Multiple devices used ({cnt})"})
    for _, r in odd_rows.iterrows():
        rows.append({"username": r['username'], "issue": f"Login at odd hour ({r['timestamp']})", "ip": r['ip'], "device": r['device']})

    flagged_df = pd.DataFrame(rows)
    return flagged_df, df

if uploaded_file:
    df = pd.read_csv(uploaded_file)
    st.subheader("Uploaded Data (first 10 rows)")
    st.dataframe(df.head(10))

    flagged_df, full_df = analyze_df(df)

    st.subheader("⚠️ Suspicious Activities")
    if flagged_df.empty:
        st.success("No suspicious activity detected with current thresholds.")
    else:
        st.dataframe(flagged_df)
        csv = flagged_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Download flagged report (CSV)", data=csv, file_name="flagged_report.csv", mime="text/csv")
else:
    st.info("Upload sample_log.csv from this project folder or your own login CSV.")
