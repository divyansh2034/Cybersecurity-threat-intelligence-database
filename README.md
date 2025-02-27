# Cybersecurity Threat Intelligence System

## Overview
This is a **Cybersecurity Threat Intelligence System** built using **Streamlit, MySQL, VirusTotal API, and NetworkX**. It allows users to:
- **Scan and analyze URLs for potential threats** using VirusTotal and a local database.
- **Visualize threat networks** using PyVis and NetworkX.
- **Store and manage cybersecurity incident reports**.
- **Authenticate users** and provide role-based access.

## Features
### 🔍 **Threat Detection**
- Users can enter a URL to scan for malicious activity.
- Uses **VirusTotal API** and a **local malicious URL database**.
- Detects phishing, malware, and suspicious patterns.

### 📊 **Network Visualization**
- Displays **malware threat connections** using **NetworkX & PyVis**.
- Graph nodes represent **malicious websites**, edges show **connections**.
- Severity levels are color-coded (🔴 Red: High, 🟠 Orange: Medium, 🟢 Green: Low).

### 🛡 **Incident Reporting & Analysis**
- Stores **scanned threats and incidents** in a **MySQL database**.
- Allows **manual submissions** and incident tracking.
- Provides **severity-based mitigation strategies**.

### 🔐 **User Authentication & Role Management**
- **Login and Sign-up system** using hashed passwords.
- Admins can **view all incident reports**.

---

## Installation
### 1️⃣ **Clone the Repository**
```sh
git clone https://github.com/your-username/cybersecurity-threat-intelligence.git
cd cybersecurity-threat-intelligence
```

### 2️⃣ **Set Up the MySQL Database**
- Create a database named `cybersecurity_db`.
- Run the following SQL script to create tables:

```sql
CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('Admin', 'Reviewer') NOT NULL
);

CREATE TABLE threat_indicator (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    website_url VARCHAR(2083) NOT NULL,
    malicious_detections INT,
    suspicious_detections INT,
    harmless_detections INT,
    severity_level INT,
    scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
```

### 3️⃣ **Install Dependencies**
```sh
pip install -r requirements.txt
```
---

## Running the Application
### **Start Streamlit App**
```sh
streamlit run app.py
```

### **Scan a URL for Threats**
1. Open the **Threat Detection** page.
2. Enter a **website URL** and click `Detect Threat`.
3. View scan results (Malicious, Suspicious, Harmless).
4. If the threat is severe, it gets added to **incident reports**.

### **View Network Visualization**
- Navigate to the **Network Analysis** page.
- See how threats are connected visually.
- Toggle **filters** like severity level.

### **Manage Incident Reports**
- Admins can view all reports in the **Reports** page.
- Users can manually submit threat analysis.

---

## Security Best Practices
✅ **Never hardcode API keys or database credentials** (use `.env` files instead).  
✅ **Rotate API keys regularly** to prevent unauthorized access.  
✅ **Enable HTTPS & secure authentication mechanisms**.  
✅ **Use a firewall & intrusion detection system (IDS/IPS)**.  

---

## Contributing
1. Fork the repo and create a new branch.
2. Implement your feature or fix a bug.
3. Submit a pull request for review.

---

## License
This project is licensed under the **MIT License**.

---

## Contact
For queries or issues, contact **div200417@gmail.com** or open a GitHub issue.

