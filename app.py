import streamlit as st
import pandas as pd
import os

from src.live_monitor import analyze_live_traffic
from src.live_model import predict_live
from src.live_agent import calculate_live_risk


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="SentinelAI",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# HEADER
# ============================================================

st.title("🛡️ SentinelAI")

st.subheader("Intelligent Network Intrusion Detection Agent")

st.write(
    "AI-powered live network traffic monitoring, "
    "anomaly detection and explainable security risk assessment."
)

st.divider()


# ============================================================
# SYSTEM STATUS
# ============================================================

st.header("🔴 Live Network Monitoring")

st.write(
    "SentinelAI captures network traffic from this computer "
    "for a short time window and analyzes it using an AI anomaly detection model."
)


# Check whether trained model exists
model_path = "models/live_isolation_forest.joblib"
scaler_path = "models/live_scaler.joblib"

if os.path.exists(model_path) and os.path.exists(scaler_path):

    st.success("🟢 Live AI Model: Ready")

else:

    st.error(
        "🔴 Live AI Model: Not Found\n\n"
        "Please train the live model first using "
        "`python src/train_live_model.py`."
    )


st.divider()


# ============================================================
# CAPTURE SETTINGS
# ============================================================

st.subheader("⚙️ Capture Settings")

col1, col2 = st.columns([2, 1])

with col1:

    duration = st.slider(
        "Network Capture Duration (seconds)",
        min_value=3,
        max_value=15,
        value=5,
        step=1
    )

with col2:

    st.write("")
    st.write("")

    start_capture = st.button(
        "🚀 Analyze Live Traffic",
        use_container_width=True
    )


# ============================================================
# LIVE TRAFFIC ANALYSIS
# ============================================================

if start_capture:

    if not os.path.exists(model_path) or not os.path.exists(scaler_path):

        st.error(
            "Live AI model is missing. "
            "Train the model before starting live monitoring."
        )

    else:

        # ----------------------------------------------------
        # CAPTURE TRAFFIC
        # ----------------------------------------------------

        st.info(
            f"📡 Capturing network traffic for {duration} seconds..."
        )

        st.write(
            "You can browse websites, refresh pages, "
            "or use normal network applications during this capture."
        )

        try:

            with st.spinner("🔍 Monitoring network traffic..."):

                live_features = analyze_live_traffic(duration)

            st.success("✅ Network capture completed!")

            # ------------------------------------------------
            # AI PREDICTION
            # ------------------------------------------------

            with st.spinner("🤖 Running AI anomaly detection..."):

                prediction, anomaly_score = predict_live(
                    live_features
                )

            # ------------------------------------------------
            # RISK SCORING
            # ------------------------------------------------

            risk, level, reasons = calculate_live_risk(
                live_features,
                prediction
            )


            # =================================================
            # LIVE TRAFFIC STATISTICS
            # =================================================

            st.divider()

            st.header("📡 Live Traffic Statistics")

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.metric(
                    "Total Packets",
                    f'{live_features["total_packets"]:,}'
                )

            with col2:

                st.metric(
                    "Total Bytes",
                    f'{live_features["total_bytes"]:,}'
                )

            with col3:

                st.metric(
                    "Packets / Second",
                    f'{live_features["packets_per_second"]:.2f}'
                )

            with col4:

                st.metric(
                    "Bytes / Second",
                    f'{live_features["bytes_per_second"]:.2f}'
                )


            # =================================================
            # PROTOCOL STATISTICS
            # =================================================

            st.subheader("🌐 Protocol & Traffic Direction")

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.metric(
                    "TCP Packets",
                    f'{live_features["tcp_packets"]:,}'
                )

            with col2:

                st.metric(
                    "UDP Packets",
                    f'{live_features["udp_packets"]:,}'
                )

            with col3:

                st.metric(
                    "Incoming Packets",
                    f'{live_features["incoming_packets"]:,}'
                )

            with col4:

                st.metric(
                    "Outgoing Packets",
                    f'{live_features["outgoing_packets"]:,}'
                )


            # =================================================
            # CONNECTION INFORMATION
            # =================================================

            st.subheader("🔗 Connection Information")

            col1, col2, col3, col4 = st.columns(4)

            with col1:

                st.metric(
                    "Forward Packets",
                    f'{live_features["forward_packets"]:,}'
                )

            with col2:

                st.metric(
                    "Backward Packets",
                    f'{live_features["backward_packets"]:,}'
                )

            with col3:

                st.metric(
                    "Unique Sources",
                    f'{live_features["unique_sources"]:,}'
                )

            with col4:

                st.metric(
                    "Unique Destinations",
                    f'{live_features["unique_destinations"]:,}'
                )


            # =================================================
            # AI DETECTION RESULT
            # =================================================

            st.divider()

            st.header("🎯 AI Detection Result")

            col1, col2, col3 = st.columns(3)

            with col1:

                st.metric(
                    "Prediction",
                    prediction
                )

            with col2:

                st.metric(
                    "Risk Score",
                    f"{risk}/100"
                )

            with col3:

                st.metric(
                    "Risk Level",
                    level
                )


            # =================================================
            # SECURITY ALERT
            # =================================================

            st.subheader("🚨 Security Alert")


            if level == "LOW":

                st.success(
                    f"🟢 LOW RISK — {risk}/100\n\n"
                    "Network traffic appears normal."
                )

            elif level == "MEDIUM":

                st.warning(
                    f"🟡 MEDIUM RISK — {risk}/100\n\n"
                    "Some unusual network behavior was detected."
                )

            elif level == "HIGH":

                st.error(
                    f"🟠 HIGH RISK — {risk}/100\n\n"
                    "Potentially suspicious network behavior detected."
                )

            else:

                st.error(
                    f"🔴 CRITICAL RISK — {risk}/100\n\n"
                    "Highly unusual network behavior detected."
                )


            # =================================================
            # SECURITY AGENT
            # =================================================

            st.divider()

            st.header("🤖 Security Agent Analysis")

            st.write(
                "**Why did the agent make this decision?**"
            )

            if reasons:

                for reason in reasons:

                    st.write(
                        f"🔹 {reason}"
                    )

            else:

                st.write(
                    "🔹 No significant suspicious indicators detected."
                )


            # =================================================
            # RECOMMENDED ACTION
            # =================================================

            st.subheader("🛡️ Recommended Action")


            if level == "LOW":

                st.info(
                    "✅ Traffic appears normal. "
                    "Continue monitoring."
                )

            elif level == "MEDIUM":

                st.warning(
                    "⚠️ Monitor the traffic closely "
                    "and investigate unusual activity."
                )

            elif level == "HIGH":

                st.warning(
                    "⚠️ Investigate the network activity, "
                    "source hosts and destination hosts."
                )

            else:

                st.error(
                    "🚨 Critical activity detected. "
                    "Investigate the traffic immediately."
                )


            # =================================================
            # ANOMALY SCORE
            # =================================================

            st.subheader("📊 AI Anomaly Score")

            st.write(
                f"Isolation Forest decision score: "
                f"**{anomaly_score:.4f}**"
            )

            st.caption(
                "The anomaly score is produced by the Isolation Forest "
                "model. More unusual observations receive lower decision scores."
            )


            # =================================================
            # LIVE FEATURE TABLE
            # =================================================

            st.divider()

            with st.expander("🔍 View All Live Network Features"):

                feature_table = pd.DataFrame(
                    list(live_features.items()),
                    columns=["Feature", "Value"]
                )

                st.dataframe(
                    feature_table,
                    use_container_width=True,
                    hide_index=True
                )


            # =================================================
            # ANALYSIS SUMMARY
            # =================================================

            st.divider()

            st.header("📋 Analysis Summary")

            summary_data = {

                "Metric": [
                    "Capture Duration",
                    "Total Packets",
                    "Total Bytes",
                    "Packets / Second",
                    "TCP Packets",
                    "UDP Packets",
                    "Incoming Packets",
                    "Outgoing Packets",
                    "AI Prediction",
                    "Risk Score",
                    "Risk Level"
                ],

                "Value": [
                    f"{duration} seconds",
                    live_features["total_packets"],
                    live_features["total_bytes"],
                    f'{live_features["packets_per_second"]:.2f}',
                    live_features["tcp_packets"],
                    live_features["udp_packets"],
                    live_features["incoming_packets"],
                    live_features["outgoing_packets"],
                    prediction,
                    f"{risk}/100",
                    level
                ]
            }

            summary_df = pd.DataFrame(summary_data)

            st.dataframe(
                summary_df,
                use_container_width=True,
                hide_index=True
            )


        # =====================================================
        # ERROR HANDLING
        # =====================================================

        except PermissionError:

            st.error(
                "❌ Permission denied while capturing network traffic.\n\n"
                "On Windows, try running VS Code as Administrator "
                "and start Streamlit again."
            )

        except Exception as e:

            st.error(
                f"❌ Live monitoring failed:\n\n{e}"
            )


# ============================================================
# INFORMATION SECTION
# ============================================================

   