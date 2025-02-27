import streamlit as st
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from api_integration import get_api_instance
from network_visualization import display_network_visualization
from style import apply_custom_style, custom_header, custom_card, custom_stat_card
import re  # Add this import at the top


# Database connection
def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",  # Replace with your MySQL username
        password="Dhruv001@",  # Replace with your MySQL password
        database="cybersecurity_db"
    )

# User authentication (login)
def authenticate_user(email, password):
    conn = connect_db()
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()
    conn.close()
    if user and check_password_hash(user[2], password):  # Compare hashed password
        return user
    return None

# User registration (sign-up)
def register_user(email, password, role):
    conn = connect_db()
    cursor = conn.cursor()
    hashed_password = generate_password_hash(password)
    query = "INSERT INTO users (email, password, role) VALUES (%s, %s, %s)"
    try:
        cursor.execute(query, (email, hashed_password, role))
        conn.commit()
        st.success("Registration successful! You can now log in.")
    except mysql.connector.IntegrityError:
        st.error("Email already exists. Please try a different one.")
    finally:
        conn.close()

# Save threat analysis results to database
def save_threat_analysis(user_id, website_link, malicious, suspicious, harmless, severity):
    # Add URL validation
    if not website_link.startswith(('http://', 'https://')):
        website_link = 'http://' + website_link
        
    conn = connect_db()
    cursor = conn.cursor()
    query = """
        INSERT INTO threat_indicator 
        (user_id, website_url, malicious_detections, suspicious_detections, 
         harmless_detections, severity_level, scan_date) 
        VALUES (%s, %s, %s, %s, %s, %s, NOW())
    """
    try:
        cursor.execute(query, (user_id, website_link, malicious, suspicious, 
                             harmless, severity))
        conn.commit()
        st.success("Scan results saved successfully!")
    except mysql.connector.Error as err:
        st.error(f"Error saving scan results: {err}")
    finally:
        conn.close()

def check_malware_repository(website_link):
    conn = connect_db()
    cursor = conn.cursor()
    query = """
        SELECT name, severity, description 
        FROM malware_repository 
        WHERE name = %s
    """
    try:
        cursor.execute(query, (website_link,))
        result = cursor.fetchone()
        if result:
            return {
                'name': result[0],
                'severity': result[1],
                'description': result[2]
            }
        return None
    except mysql.connector.Error as err:
        st.error(f"Error checking malware repository: {err}")
        return None
    finally:
        conn.close()

def save_incident_report(user_id, website_link, severity, malicious_detections, resolution_status="Unresolved"):
    conn = connect_db()
    cursor = conn.cursor()
    query = """
        INSERT INTO incident_reports 
        (user_id, malicious_url, severity_level, malicious_detections, 
         report_date, resolution_status) 
        VALUES (%s, %s, %s, %s, NOW(), %s)
    """
    try:
        cursor.execute(query, (user_id, website_link, severity, malicious_detections, 
                             resolution_status))
        conn.commit()
        st.warning("⚠️ Due to malicious content detected, this URL has been added to incident reports.")
    except mysql.connector.Error as err:
        st.error(f"Error saving incident report: {err}")
    finally:
        conn.close()

def show_reports_page():
    st.header("Threat Analysis Reports")
    
    # Create tabs for different report types
    tab1, tab2 = st.tabs(["Incident Reports", "Manual Submissions"])
    
    with tab1:
        st.subheader("Incident Reports")
        
        # Filtering options
        col1, col2 = st.columns(2)
        with col1:
            severity_filter = st.selectbox(
                "Filter by Severity",
                ["All", "High (7-10)", "Medium (4-6)", "Low (1-3)"]
            )
        with col2:
            date_filter = st.selectbox(
                "Filter by Date",
                ["All Time", "Last 7 Days", "Last 30 Days", "Last 3 Months"]
            )
        
        # Get filtered incident reports
        reports = get_filtered_incident_reports(severity_filter, date_filter)
        
        if reports:
            for report in reports:
                with st.expander(f"URL: {report['malicious_url']} (Severity: {report['severity_level']})"):
                    st.write(f"Reported by: {report['email']}")
                    st.write(f"Malicious Detections: {report['malicious_detections']}")
                    st.write(f"Status: {report['resolution_status']}")
                    st.write(f"Date: {report['report_date']}")
    
    with tab2:
        st.subheader("Manual Threat Submissions")
        
        # Form for manual submission
        with st.expander("Submit New Threat Analysis"):
            url = st.text_input("URL")
            severity = st.slider("Severity Level", 1, 10, 5)
            description = st.text_area("Description")
            analysis = st.text_area("Analysis Results")
            
            if st.button("Submit Analysis"):
                save_manual_submission(
                    st.session_state.user_id,
                    url,
                    severity,
                    description,
                    analysis
                )
                st.success("Analysis submitted successfully!")
        
        # Display manual submissions
        st.subheader("Previous Submissions")
        submissions = get_manual_submissions()
        
        if submissions:
            for sub in submissions:
                with st.expander(f"URL: {sub['url']} (Severity: {sub['severity_level']})"):
                    st.write(f"Submitted by: {sub['email']}")
                    st.write(f"Description: {sub['description']}")
                    st.write(f"Analysis: {sub['analysis_result']}")
                    st.write(f"Date: {sub['submitted_at']}")

def get_filtered_incident_reports(severity_filter, date_filter):
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT ir.*, u.email 
        FROM incident_reports ir
        JOIN users u ON ir.user_id = u.user_id
        WHERE 1=1
    """
    
    params = []
    
    # Add severity filter
    if severity_filter != "All":
        if severity_filter == "High (7-10)":
            query += " AND severity_level >= 7"
        elif severity_filter == "Medium (4-6)":
            query += " AND severity_level BETWEEN 4 AND 6"
        elif severity_filter == "Low (1-3)":
            query += " AND severity_level < 4"
    
    # Add date filter
    if date_filter != "All Time":
        if date_filter == "Last 7 Days":
            query += " AND report_date >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        elif date_filter == "Last 30 Days":
            query += " AND report_date >= DATE_SUB(NOW(), INTERVAL 30 DAY)"
        elif date_filter == "Last 3 Months":
            query += " AND report_date >= DATE_SUB(NOW(), INTERVAL 3 MONTH)"
    
    query += " ORDER BY report_date DESC"
    
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    except mysql.connector.Error as err:
        st.error(f"Error fetching reports: {err}")
        return []
    finally:
        conn.close()

def save_manual_submission(user_id, url, severity, description, analysis):
    conn = connect_db()
    cursor = conn.cursor()
    
    query = """
        INSERT INTO threat_analysis_submissions 
        (submitted_by, url, severity_level, description, analysis_result)
        VALUES (%s, %s, %s, %s, %s)
    """
    
    try:
        cursor.execute(query, (user_id, url, severity, description, analysis))
        conn.commit()
    except mysql.connector.Error as err:
        st.error(f"Error saving submission: {err}")
    finally:
        conn.close()

def get_manual_submissions():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    
    query = """
        SELECT tas.*, u.email 
        FROM threat_analysis_submissions tas
        JOIN users u ON tas.submitted_by = u.user_id
        ORDER BY submitted_at DESC
    """
    
    try:
        cursor.execute(query)
        return cursor.fetchall()
    except mysql.connector.Error as err:
        st.error(f"Error fetching submissions: {err}")
        return []
    finally:
        conn.close()

# Add this function for email validation
def is_valid_email(email):
    """Validate email format using regex pattern"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Add this function at the top with other helper functions
def get_mitigation_strategy(severity):
    strategies = {
        1: "No action needed; maintain regular security updates.",
        2: "Monitor network logs and ensure firewall is enabled.",
        3: "Use strong passwords and enable 2FA for all accounts.",
        4: "Perform regular vulnerability assessments.",
        5: "Educate users about phishing and implement email filtering.",
        6: "Install and update endpoint protection software.",
        7: "Restrict access to critical systems and apply least privilege.",
        8: "Enable IDS/IPS and conduct continuous threat monitoring.",
        9: "Isolate infected systems, apply patches immediately.",
        10: "Immediate incident response, full forensic analysis, and containment."
    }
    return strategies.get(round(severity), "Maintain standard security practices.")

# Streamlit app
def main():
    # Apply custom styling
    apply_custom_style()
    
    # Custom title with cyberpunk style
    st.markdown("""
        <h1 class="stTitle">Cybersecurity Intelligent<br>Threat Detection</h1>
    """, unsafe_allow_html=True)

    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if not st.session_state.logged_in:
        # Sign-In or Sign-Up Options
        option = st.selectbox("Choose an option", ["Login", "Sign Up"])

        if option == "Login":
            st.header("Login")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            
            if st.button("Login"):
                if not email:
                    st.error("Please enter your email.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                elif not password:
                    st.error("Please enter your password.")
                else:
                    user = authenticate_user(email, password)
                    if user:
                        st.session_state.logged_in = True
                        st.session_state.user_id = user[0]
                        st.session_state.role = user[3]
                        st.success("Logged in successfully!")
                    else:
                        st.error("Invalid email or password.")

        elif option == "Sign Up":
            st.header("Sign Up")
            email = st.text_input("Email")
            password = st.text_input("Password", type="password")
            confirm_password = st.text_input("Confirm Password", type="password")
            role = st.selectbox("Role", ["Admin", "Reviewer"])
            
            if st.button("Sign Up"):
                if not email:
                    st.error("Please enter your email.")
                elif not is_valid_email(email):
                    st.error("Please enter a valid email address.")
                elif not password:
                    st.error("Please enter a password.")
                elif password != confirm_password:
                    st.error("Passwords do not match.")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters long.")
                else:
                    register_user(email, password, role)
        return

    # Custom navigation header with logout button
    st.sidebar.markdown("""
        <div class="nav-header">
            <h3>NAVIGATION CONSOLE</h3>
        </div>
    """, unsafe_allow_html=True)
    
    # Add logout button to sidebar
    if st.sidebar.button("🔒 Logout", key="logout_button"):
        st.session_state.clear()  # Clear all session state
        st.rerun()  # Use st.rerun() instead of experimental_rerun()
    
    # Add a divider in sidebar
    st.sidebar.markdown("<hr style='border: 1px solid #0fe0b0; margin: 20px 0;'>", unsafe_allow_html=True)
    
    # Custom navigation options
    nav_options = ["Threat Detection", "Reports", "Network Analysis"]
    page = st.sidebar.selectbox("", nav_options, 
        format_func=lambda x: f">> {x}")
    
    if page == "Threat Detection":
        custom_header("Threat Analysis Console")
        # Main app after login
        st.header("Threat Detection")
        website_link = st.text_input("Enter website link to analyze:")
        if st.button("Detect Threat"):
            if website_link:
                with st.spinner('Analyzing website...'):
                    if not website_link.startswith(('http://', 'https://')):
                        website_link = 'http://' + website_link

                    api = get_api_instance()
                    scan_results = api.scan_url(website_link, st.session_state.user_id)
                    
                    if scan_results:
                        # Display scan results
                        st.write("Scan Results:")
                        st.write(f"- Malicious Score: {scan_results['malicious']}")
                        st.write(f"- Suspicious Score: {scan_results['suspicious']}")
                        st.write(f"- Harmless Score: {scan_results['harmless']}")
                        
                        if scan_results.get('patterns_detected'):
                            st.warning("Suspicious Patterns Detected:")
                            for pattern in scan_results['patterns_detected']:
                                st.write(f"- Pattern: {pattern['pattern']} (Type: {pattern['type']})")
                        
                        if scan_results.get('local_database_match'):
                            st.error("⚠️ URL matches known malicious patterns in local database!")
                        
                        # Save results to threat_indicator table (only once)
                        save_threat_analysis(
                            st.session_state.user_id,
                            website_link,
                            scan_results['malicious'],
                            scan_results['suspicious'],
                            scan_results['harmless'],
                            scan_results['severity']
                        )
                        
                        # Check if URL should be reported (malicious or high severity)
                        should_report = (
                            scan_results['malicious'] > 0 or 
                            scan_results['severity'] >= 7 or 
                            (scan_results['suspicious'] > 0 and scan_results['severity'] >= 5)
                        )
                        
                        if should_report:
                            # Check malware repository
                            known_malware = check_malware_repository(website_link)
                            
                            if known_malware:
                                st.error("🚨 ALERT: Known Malicious URL Detected! 🚨")
                                st.error(f"Malware Name: {known_malware['name']}")
                                st.error(f"Severity Level: {known_malware['severity']}/10")
                                st.warning(f"Description: {known_malware['description']}")
                                resolution_status = "Known Threat"
                            else:
                                if scan_results['malicious'] > 0:
                                    st.error("🚨 New Malicious URL Detected!")
                                    resolution_status = "Unresolved - Malicious"
                                else:
                                    st.warning("⚠️ Suspicious URL Detected!")
                                    resolution_status = "Unresolved - Suspicious"
                            
                            # Save to incident report
                            save_incident_report(
                                st.session_state.user_id,
                                website_link,
                                scan_results['severity'],
                                scan_results['malicious'],
                                resolution_status
                            )
                            
                            # Additional user guidance
                            st.info("👉 Security team has been notified and will investigate this threat.")
                            if scan_results['severity'] >= 8:
                                st.error("⚠️ CRITICAL: Immediate action recommended. Avoid accessing this URL.")
                        
                        # Display severity level message
                        severity = round(scan_results['severity'])
                        if severity >= 7:
                            st.error(f"High threat level detected! Severity: {severity}/10")
                        elif severity >= 4:
                            st.warning(f"Medium threat level detected. Severity: {severity}/10")
                        else:
                            st.success(f"Low threat level. Severity: {severity}/10")

                        # Get mitigation strategy
                        mitigation = get_mitigation_strategy(severity)
                        
                        # Create styled container for recommendation
                        st.markdown("---")  # Add a separator
                        st.markdown("""
                            <h3 style='color: #0fe0b0; margin: 20px 0;'>🛡️ Recommended Action</h3>
                        """, unsafe_allow_html=True)
                        
                        # Display recommendation in a styled container
                        st.markdown(f"""
                            <div style='
                                background: rgba(0, 0, 0, 0.8);
                                border: 1px solid #0fe0b0;
                                border-radius: 5px;
                                padding: 20px;
                                margin: 10px 0;
                            '>
                                <div style='
                                    color: #0fe0b0;
                                    font-family: "Courier New", monospace;
                                    margin-bottom: 10px;
                                '>
                                    Severity Level: {severity}/10
                                </div>
                                <div style='
                                    color: #0fe0b0;
                                    font-family: "Courier New", monospace;
                                    padding: 10px;
                                    background: rgba(15, 224, 176, 0.05);
                                    border-left: 3px solid #0fe0b0;
                                '>
                                    {mitigation}
                                </div>
                            </div>
                        """, unsafe_allow_html=True)
                    else:
                        st.error("Failed to analyze website. Please try again later.")
            else:
                st.warning("Please enter a website link.")
    elif page == "Reports":
        show_reports_page()
    elif page == "Network Analysis":
        display_network_visualization()

if __name__ == "__main__":
    main()
