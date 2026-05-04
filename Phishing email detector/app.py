import streamlit as st
import pandas as pd
import time
import joblib
import os
import matplotlib.pyplot as plt
import seaborn as sns
from predict import PhishingDetector
from feature_extractor import extract_advanced_features

# Page Config
st.set_page_config(
    page_title="Phishing Email Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark-themed custom CSS for Cybersecurity UI
st.markdown("""
<style>
    /* Main Background */
    .stApp {
        background-color: #0e1117;
        color: #e0e6ed;
    }
    
    /* Risk Meter Box */
    .risk-meter {
        padding: 20px;
        border-radius: 10px;
        margin-top: 20px;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    .high-risk {
        background: linear-gradient(135deg, #4b0000 0%, #8b0000 100%);
        border: 1px solid #ff3333;
    }
    
    .low-risk {
        background: linear-gradient(135deg, #002b12 0%, #004d22 100%);
        border: 1px solid #00cc66;
    }
    
    .metric-value {
        font-size: 3rem;
        font-weight: 700;
        margin: 10px 0;
    }
    
    /* Advanced Features Table */
    .feature-row {
        display: flex;
        justify-content: space-between;
        padding: 10px;
        border-bottom: 1px solid #333;
    }
</style>
""", unsafe_allow_html=True)

# Helper function to load model
@st.cache_resource
def load_detector():
    if os.path.exists("models/phishing_model.pkl"):
        return PhishingDetector()
    return None

def main():
    # Sidebar
    st.sidebar.title("🛡️ CyberShield ML")
    st.sidebar.markdown("---")
    st.sidebar.info(
        "**Phishing Email Detection Engine**\n\n"
        "This tool uses Machine Learning and NLP to scan emails for malicious intent, "
        "suspicious URLs, and threat vectors."
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### System Status")
    
    detector = load_detector()
    
    if detector:
        st.sidebar.success("✅ Model Loaded & Active")
    else:
        st.sidebar.error("❌ Model Not Found. Train it first!")

    # Main UI
    st.title("🛡️ Advanced Phishing Email Detector")
    st.markdown("Enter email content below to scan for phishing attempts, malicious links, and dangerous keywords.")

    email_input = st.text_area("📨 Paste Email Content Here:", height=200, 
                             placeholder="Example: URGENT! Verify your bank account immediately...")

    col1, col2 = st.columns([1, 4])
    with col1:
        analyze_btn = st.button("🔍 Scan Email", use_container_width=True, type="primary")

    if analyze_btn:
        if not email_input.strip():
            st.warning("Please enter some text to analyze.")
        elif not detector:
            st.error("Model is not trained. Please run `python train.py` first.")
        else:
            with st.spinner("Analyzing threat vectors..."):
                time.sleep(1) # Simulate deep scan
                
                prediction, risk_score, features = detector.predict(email_input)
                
                # Layout for results
                res_col1, res_col2 = st.columns([2, 1])
                
                with res_col1:
                    st.subheader("Analysis Report")
                    
                    if prediction == 1:
                        # Phishing
                        st.markdown(f"""
                        <div class="risk-meter high-risk">
                            <h2 style="color: #ff6666;">⚠️ THREAT DETECTED: PHISHING</h2>
                            <div class="metric-value" style="color: #ff9999;">{risk_score:.1f}%</div>
                            <p>Confidence Level / Risk Score</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        # Safe
                        st.markdown(f"""
                        <div class="risk-meter low-risk">
                            <h2 style="color: #66ff99;">✅ SAFE EMAIL</h2>
                            <div class="metric-value" style="color: #99ffbb;">{100 - risk_score:.1f}%</div>
                            <p>Safety Confidence</p>
                        </div>
                        """, unsafe_allow_html=True)
                        
                with res_col2:
                    st.subheader("Threat Indicators")
                    st.markdown("---")
                    
                    st.markdown(f"""
                    <div class="feature-row">
                        <span>🔗 URLs Found</span>
                        <strong>{features['num_urls']}</strong>
                    </div>
                    <div class="feature-row">
                        <span>❗ Urgent Language</span>
                        <strong>{'Yes' if features['has_urgent_words'] else 'No'}</strong>
                    </div>
                    <div class="feature-row">
                        <span>💰 Financial Keywords</span>
                        <strong>{'Yes' if features['has_financial_words'] else 'No'}</strong>
                    </div>
                    <div class="feature-row">
                        <span>! Exclamation Marks</span>
                        <strong>{features['num_exclamations']}</strong>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Radar chart or bar chart for visual appeal
                st.markdown("### Threat Breakdown")
                
                chart_data = pd.DataFrame({
                    'Metric': ['Risk Score', 'URL Density', 'Urgency', 'Financial'],
                    'Value': [
                        risk_score, 
                        min(100, features['num_urls'] * 20), 
                        100 if features['has_urgent_words'] else 0,
                        100 if features['has_financial_words'] else 0
                    ]
                })
                
                fig, ax = plt.subplots(figsize=(10, 2))
                sns.barplot(x='Value', y='Metric', data=chart_data, palette='Reds_r' if prediction == 1 else 'Greens_r')
                ax.set_xlim(0, 100)
                plt.tight_layout()
                
                # Custom dark theme for matplotlib
                fig.patch.set_facecolor('#0e1117')
                ax.set_facecolor('#0e1117')
                ax.tick_params(colors='white')
                ax.xaxis.label.set_color('white')
                ax.yaxis.label.set_color('white')
                ax.title.set_color('white')
                
                st.pyplot(fig)

if __name__ == "__main__":
    main()
