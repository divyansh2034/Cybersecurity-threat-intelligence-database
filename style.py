import streamlit as st

def apply_custom_style():
    st.markdown("""
        <style>
        /* Animated gradient background */
        @keyframes gradientBG {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }

        @keyframes pulse {
            0% { opacity: 0.4; }
            50% { opacity: 0.7; }
            100% { opacity: 0.4; }
        }

        @keyframes glitch {
            0% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; }
            15% { text-shadow: 0.05em 0 0 #00fffc, -0.03em -0.04em 0 #fc00ff; }
            16% { text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff; }
            49% { text-shadow: -0.05em -0.025em 0 #00fffc, 0.025em 0.035em 0 #fc00ff; }
            50% { text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff; }
            99% { text-shadow: 0.05em 0.035em 0 #00fffc, 0.03em 0 0 #fc00ff; }
            100% { text-shadow: -0.05em 0 0 #00fffc, -0.025em -0.04em 0 #fc00ff; }
        }

        /* Base styles */
        section[data-testid="stSidebar"] {
            background-color: rgba(0, 0, 0, 0.95);
            border-right: 2px solid #0fe0b0;
            animation: pulse 4s ease-in-out infinite;
        }

        /* Main container */
        .main {
            background-color: rgba(0, 0, 0, 0.95);
            color: #0fe0b0;
        }

        /* Background with animated grid */
        .stApp {
            background: linear-gradient(-45deg, #000000, #0a0a0a, #000000, #0f1515);
            background-size: 400% 400%;
            animation: gradientBG 15s ease infinite;
        }

        .stApp::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                linear-gradient(90deg, rgba(15, 224, 176, 0.07) 1px, transparent 1px),
                linear-gradient(0deg, rgba(15, 224, 176, 0.07) 1px, transparent 1px),
                linear-gradient(90deg, rgba(15, 224, 176, 0.05) 0.5px, transparent 0.5px),
                linear-gradient(0deg, rgba(15, 224, 176, 0.05) 0.5px, transparent 0.5px);
            background-size: 30px 30px;
            pointer-events: none;
            animation: pulse 3s ease-in-out infinite;
        }

        /* Enhanced title with glitch effect */
        .stTitle, .main-title {
            color: #0fe0b0 !important;
            text-shadow: 0 0 10px rgba(15, 224, 176, 0.5);
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 3px;
            text-align: center;
            padding: 20px;
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #0fe0b0;
            border-radius: 5px;
            margin-bottom: 2rem;
            animation: glitch 3s infinite;
            position: relative;
            overflow: hidden;
        }

        /* Glowing border effect */
        .stcard::after, .stat-card::after {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: linear-gradient(
                45deg,
                transparent 0%,
                rgba(15, 224, 176, 0.1) 50%,
                transparent 100%
            );
            transform: rotate(45deg);
            animation: shine 6s linear infinite;
        }

        @keyframes shine {
            0% { transform: translateX(-100%) rotate(45deg); }
            100% { transform: translateX(100%) rotate(45deg); }
        }

        /* Button hover effect */
        .stButton>button:hover {
            background: #0fe0b0 !important;
            color: black !important;
            box-shadow: 0 0 15px rgba(15, 224, 176, 0.5);
            transform: translateY(-2px);
            transition: all 0.3s ease;
        }

        /* Stats card pulsing effect */
        .stat-value {
            animation: pulse 2s infinite;
        }

        /* Card styling */
        .stcard, .stat-card {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #0fe0b0;
            box-shadow: 0 0 15px rgba(15, 224, 176, 0.2);
            padding: 1rem;
            border-radius: 5px;
            margin: 1rem 0;
        }

        /* Button styling */
        .stButton>button {
            background: rgba(0, 0, 0, 0.8) !important;
            color: #0fe0b0 !important;
            border: 1px solid #0fe0b0 !important;
            border-radius: 5px;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
        }

        /* Input fields */
        .stTextInput>div>div>input {
            background-color: rgba(0, 0, 0, 0.8) !important;
            color: #0fe0b0 !important;
            border: 1px solid #0fe0b0 !important;
            border-radius: 5px;
        }

        /* Text elements */
        .stMarkdown, p, .stText {
            color: #0fe0b0 !important;
        }

        h1, h2, h3 {
            color: #0fe0b0 !important;
            text-shadow: 0 0 10px rgba(15, 224, 176, 0.3);
        }

        /* Selectbox styling */
        .stSelectbox > div > div {
            background-color: rgba(0, 0, 0, 0.8) !important;
            border: 1px solid #0fe0b0 !important;
            color: #0fe0b0 !important;
        }

        /* Navigation header */
        .nav-header {
            color: #0fe0b0;
            text-align: center;
            padding: 15px 0;
            margin-bottom: 20px;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 0 10px rgba(15, 224, 176, 0.3);
        }

        .nav-header h3 {
            margin: 0;
            font-size: 1.2rem;
        }

        /* Logout button */
        [data-testid="stButton"] button[kind="secondary"] {
            background: rgba(0, 0, 0, 0.8) !important;
            color: #ff4757 !important;
            border: 1px solid #ff4757 !important;
            border-radius: 5px;
            padding: 0.5rem 1rem;
            transition: all 0.3s ease;
            width: 100%;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 2px;
        }

        [data-testid="stButton"] button[kind="secondary"]:hover {
            background: #ff4757 !important;
            color: black !important;
            box-shadow: 0 0 20px rgba(255, 71, 87, 0.5);
            transform: translateY(-2px);
        }

        /* Scrollbar */
        ::-webkit-scrollbar {
            width: 10px;
            background: rgba(0, 0, 0, 0.5);
        }

        ::-webkit-scrollbar-thumb {
            background: #0fe0b0;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(15, 224, 176, 0.5);
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #0bc192;
        }

        /* Selection */
        ::selection {
            background: rgba(15, 224, 176, 0.3);
            color: #0fe0b0;
        }

        /* Customize top menu bar */
        header[data-testid="stHeader"] {
            background-color: rgba(0, 0, 0, 0.95);
            border-bottom: 1px solid #0fe0b0;
        }

        .stDeployButton {
            display: none;  /* Hide deploy button */
        }

        /* Style the hamburger menu */
        button[kind="header"] {
            background-color: transparent !important;
            color: #0fe0b0 !important;
        }

        button[kind="header"]:hover {
            background-color: rgba(15, 224, 176, 0.1) !important;
            color: #0fe0b0 !important;
        }

        /* Style the menu dropdown */
        .stToolbar {
            background-color: rgba(0, 0, 0, 0.95) !important;
            border: 1px solid #0fe0b0 !important;
            color: #0fe0b0 !important;
        }

        /* Menu items */
        .stToolbar button {
            color: #0fe0b0 !important;
        }

        .stToolbar button:hover {
            background-color: rgba(15, 224, 176, 0.1) !important;
        }

        /* Mitigation Strategy Card Styling */
        .mitigation-card {
            background: rgba(0, 0, 0, 0.8);
            border: 1px solid #0fe0b0;
            border-radius: 5px;
            padding: 20px;
            margin: 20px 0;
            position: relative;
            overflow: hidden;
        }

        .mitigation-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(
                90deg,
                transparent,
                #0fe0b0,
                transparent
            );
            animation: scanline 2s linear infinite;
        }

        @keyframes scanline {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        .mitigation-header {
            color: #0fe0b0;
            font-family: 'Courier New', monospace;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .mitigation-content {
            color: #0fe0b0;
            font-family: 'Courier New', monospace;
            line-height: 1.6;
            padding: 10px;
            background: rgba(15, 224, 176, 0.05);
            border-left: 3px solid #0fe0b0;
        }

        /* Severity level badges */
        .severity-high {
            color: #ff4757;
            border-color: #ff4757;
        }

        .severity-medium {
            color: #ffa502;
            border-color: #ffa502;
        }

        .severity-low {
            color: #2ed573;
            border-color: #2ed573;
        }
        </style>
    """, unsafe_allow_html=True)

def custom_header(title):
    return st.markdown(f"""
        <div class="title-container">
            <h1 class="main-title">{title}</h1>
        </div>
    """, unsafe_allow_html=True)

def custom_card(content, card_type="default"):
    if card_type == "mitigation":
        return st.markdown(f"""
            <div class="mitigation-card">
                {content}
            </div>
        """, unsafe_allow_html=True)
    else:
        return st.markdown(f"""
            <div class="stcard">
                {content}
            </div>
        """, unsafe_allow_html=True)

def custom_stat_card(title, value, description):
    return st.markdown(f"""
        <div class="stat-card">
            <h3 style="color: #0fe0b0;">{title}</h3>
            <div class="stat-value">{value}</div>
            <p style="color: #0fe0b0; opacity: 0.8;">{description}</p>
        </div>
    """, unsafe_allow_html=True) 