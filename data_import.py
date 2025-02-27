import pandas as pd

data = {
    "Severity Level": list(range(1, 11)),
    "Mitigation Strategies": [
        "No action needed; maintain regular security updates.",
        "Monitor network logs and ensure firewall is enabled.",
        "Use strong passwords and enable 2FA for all accounts.",
        "Perform regular vulnerability assessments.",
        "Educate users about phishing and implement email filtering.",
        "Install and update endpoint protection software.",
        "Restrict access to critical systems and apply least privilege.",
        "Enable IDS/IPS and conduct continuous threat monitoring.",
        "Isolate infected systems, apply patches immediately.",
        "Immediate incident response, full forensic analysis, and containment."
    ]
}

df = pd.DataFrame(data)

# Save as CSV and Excel
df.to_csv("cybersecurity_severity_levels.csv", index=False)