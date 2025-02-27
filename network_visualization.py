import networkx as nx
from pyvis.network import Network
import mysql.connector
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from style import custom_header, custom_card, custom_stat_card


def connect_db():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Dhruv001@",
        database="cybersecurity_db"
    )

class MalwareNetworkVisualizer:
    def __init__(self):
        self.G = nx.Graph()
        self.net = Network(height="750px", width="100%", bgcolor="#ffffff", font_color="black")
        self.net.toggle_physics(True)
        
    def get_threat_data(self):
        """Fetch threat data from database"""
        conn = connect_db()
        query = """
            SELECT ti.website_url, ti.severity_level, ti.malicious_detections,
                   ti.suspicious_detections, u.email
            FROM threat_indicator ti
            JOIN users u ON ti.user_id = u.user_id
            ORDER BY ti.scan_date DESC
            LIMIT 50
        """
        return pd.read_sql(query, conn)

    def get_color_by_severity(self, severity):
        """Return color based on severity level"""
        if severity >= 8:
            return "#ff0000"  # Red for high severity
        elif severity >= 5:
            return "#ffa500"  # Orange for medium severity
        else:
            return "#00ff00"  # Green for low severity

    def create_network_graph(self, min_severity=1, show_connections=True):
        """Create and return network visualization"""
        # Get threat data
        df = self.get_threat_data()
        
        # Filter data based on minimum severity
        df = df[df['severity_level'] >= min_severity]
        
        # Create nodes for unique domains
        for _, row in df.iterrows():
            self.G.add_node(row['website_url'], 
                           title=f"Severity: {row['severity_level']}\nDetected by: {row['email']}",
                           size=20 + (row['severity_level'] * 2),
                           color=self.get_color_by_severity(row['severity_level']))

        # Create edges between nodes with similar severity levels if show_connections is True
        if show_connections:
            for i, row1 in df.iterrows():
                for j, row2 in df.iterrows():
                    if i < j:
                        severity_diff = abs(row1['severity_level'] - row2['severity_level'])
                        if severity_diff <= 2:  # Connect nodes with similar severity
                            weight = 1 + (10 - severity_diff) / 2
                            self.G.add_edge(row1['website_url'], row2['website_url'], 
                                          weight=weight,
                                          title=f"Severity Difference: {severity_diff}")

        # Convert NetworkX graph to PyVis network
        self.net.from_nx(self.G)
        
        # Add legend
        self.net.add_node("High Severity", color="#ff0000", size=20, x=100, y=-100)
        self.net.add_node("Medium Severity", color="#ffa500", size=20, x=100, y=0)
        self.net.add_node("Low Severity", color="#00ff00", size=20, x=100, y=100)
        
        # Save and return the HTML
        self.net.save_graph("threat_network.html")
        
        with open("threat_network.html", 'r', encoding='utf-8') as f:
            html = f.read()
        
        return html

def get_current_network_data():
    """Fetch current data from database for network visualization"""
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Dhruv001@",
        database="cybersecurity_db"
    )
    cursor = conn.cursor(dictionary=True)

    # Get current incident reports
    query = """
        SELECT ir.*, u.email 
        FROM incident_reports ir
        JOIN users u ON ir.user_id = u.user_id
        ORDER BY report_date DESC
    """
    
    try:
        cursor.execute(query)
        incidents = cursor.fetchall()
        
        # Create nodes and edges based on current data
        nodes = []
        edges = []
        
        # Add user nodes
        users = set()
        for incident in incidents:
            users.add(incident['email'])
            
        for user in users:
            nodes.append({
                'id': user,
                'label': user,
                'group': 'users'
            })
            
        # Add incident nodes and edges
        for incident in incidents:
            incident_id = f"incident_{incident['id']}"
            nodes.append({
                'id': incident_id,
                'label': f"Severity: {incident['severity_level']}\n{incident['malicious_url']}",
                'group': 'incidents'
            })
            edges.append({
                'from': incident['email'],
                'to': incident_id
            })
            
        return nodes, edges
            
    except Exception as e:
        st.error(f"Error fetching network data: {e}")
        return [], []
    finally:
        cursor.close()
        conn.close()

def display_network_visualization():
    custom_header("Malware Network Visualization")
    """Display the network visualization in Streamlit"""
    st.header("Malware Network Visualization")
    
    # Add filters
    col1, col2 = st.columns(2)
    with col1:
        min_severity = st.slider("Minimum Severity", 1, 10, 1)
    with col2:
        show_connections = st.checkbox("Show Connections", True)
    
    # Get current data
    nodes, edges = get_current_network_data()
    
    # Create and display visualization with filters
    visualizer = MalwareNetworkVisualizer()
    html = visualizer.create_network_graph(min_severity=min_severity, show_connections=show_connections)
    
    # Display statistics
    df = visualizer.get_threat_data()
    filtered_df = df[df['severity_level'] >= min_severity]
    
    st.write(f"""
    ### Network Statistics
    - Total Threats Displayed: {len(filtered_df)}
    - High Severity Threats (8-10): {len(filtered_df[filtered_df['severity_level'] >= 8])}
    - Medium Severity Threats (5-7): {len(filtered_df[(filtered_df['severity_level'] >= 5) & (filtered_df['severity_level'] < 8)])}
    - Low Severity Threats (1-4): {len(filtered_df[filtered_df['severity_level'] < 5])}
    """)
    
    # Display explanation
    st.info("""
    Network Visualization Guide:
    - Red nodes: High severity threats (8-10)
    - Orange nodes: Medium severity threats (5-7)
    - Green nodes: Low severity threats (1-4)
    - Node size indicates severity level
    - Connections show related threats
    - Hover over nodes for details
    """)
    
    # Display the network graph
    components.html(html, height=800) 