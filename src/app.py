import os
import joblib
import pandas as pd
import streamlit as st
import plotly.express as px

st.set_page_config(page_title="AI Network Intrusion Detection System", layout="wide")

BASE_DIR = os.path.dirname(__file__)
MODEL_DIR = os.path.join(BASE_DIR, '..', 'models')
DATA_PATH = os.path.join(BASE_DIR, '..', 'data', 'raw', 'cicids2017_cleaned.csv')

@st.cache_resource
def load_artifacts():
    model = joblib.load(os.path.join(MODEL_DIR, 'random_forest_model.pkl'))
    scaler = joblib.load(os.path.join(MODEL_DIR, 'scaler.pkl'))
    label_encoder = joblib.load(os.path.join(MODEL_DIR, 'label_encoder.pkl'))
    feature_names = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))
    return model, scaler, label_encoder, feature_names

with st.spinner("Loading AI model artifacts..."):
    model, scaler, label_encoder, feature_names = load_artifacts()

st.title("🛡️️ AI-Based Network Intrusion Detection System")
st.markdown("Real-time and batch network traffic classification powered by Random Forest.")

menu = st.sidebar.radio("Navigation", ["Attack Signature Tester", "Batch Traffic Analysis", "Model Details"])

if menu == "Attack Signature Tester":
    st.header("⚡ Test Dataset Attack Signatures")
    st.write("Extract known samples from the dataset and evaluate model classification in real-time.")

    if st.button("Sample & Evaluate Attacks", type="primary"):
        with st.spinner("Extracting samples and predicting..."):
            df = pd.read_csv(DATA_PATH)
            df.columns = df.columns.str.strip()
            samples = df.groupby('Attack Type', as_index=False).first()

            results = []
            for _, row in samples.iterrows():
                actual = row['Attack Type']
                features = pd.DataFrame([row[feature_names]])
                scaled = scaler.transform(features)
                pred_num = model.predict(scaled)[0]
                pred_label = label_encoder.inverse_transform([pred_num])[0]

                results.append({
                    "Actual Attack Type": actual,
                    "AI Prediction": pred_label,
                    "Status": "MATCH" if actual == pred_label else "MISMATCH"
                })

            res_df = pd.DataFrame(results)
            st.dataframe(res_df, use_container_width=True)

            fig = px.bar(
                res_df,
                x="Actual Attack Type",
                color="Status",
                color_discrete_map={"MATCH": "#28a745", "MISMATCH": "#dc3545"},
                title="Classification Accuracy per Category"
            )
            st.plotly_chart(fig, use_container_width=True)

elif menu == "Batch Traffic Analysis":
    st.header("📂 Analyze Batch Traffic Log")
    uploaded_file = st.file_uploader("Upload a CSV file containing flow metrics", type=["csv"])

    if uploaded_file is not None:
        batch_df = pd.read_csv(uploaded_file)
        batch_df.columns = batch_df.columns.str.strip()
        
        missing = [col for col in feature_names if col not in batch_df.columns]
        if missing:
            st.error(f"Missing required feature columns: {missing[:5]}...")
        else:
            with st.spinner("Analyzing flows..."):
                scaled = scaler.transform(batch_df[feature_names])
                preds = model.predict(scaled)
                labels = label_encoder.inverse_transform(preds)
                batch_df["Prediction"] = labels

            st.success(f"Analysis complete on {len(batch_df)} flow records.")
            
            normal_count = int((batch_df["Prediction"] == "Normal Traffic").sum())
            attack_count = len(batch_df) - normal_count

            col1, col2 = st.columns(2)
            col1.metric("Normal Traffic Flows", f"{normal_count:,}")
            col2.metric("Detected Threats", f"{attack_count:,}", delta_color="inverse")

            dist = batch_df["Prediction"].value_counts().reset_index()
            dist.columns = ["Traffic Type", "Count"]
            fig = px.pie(dist, names="Traffic Type", values="Count", title="Detected Traffic Distribution", hole=0.4)
            st.plotly_chart(fig, use_container_width=True)

            st.dataframe(batch_df.head(50), use_container_width=True)

elif menu == "Model Details":
    st.header("🧠 Model Architecture & Metrics")
    st.markdown("""
    - **Algorithm:** Random Forest Classifier (50 Estimators, Parallel CPU Execution)
    - **Accuracy:** ~99.90% on CICIDS2017 benchmark
    - **Monitored Features:** 52 Statistical Flow Parameters
    - **Detection Scope:** DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Botnets, Normal Traffic
    """)
    st.write("Registered Features:")
    st.json(feature_names)