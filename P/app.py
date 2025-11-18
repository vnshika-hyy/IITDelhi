# app.py
import streamlit as st
import pandas as pd
import numpy as np
import joblib
import sys
import os
from datetime import datetime
from urllib.parse import urlparse
import warnings
import plotly.express as px
import plotly.graph_objects as go
import io
import base64
import re
import socket
import whois
import dns.resolver
from concurrent.futures import ThreadPoolExecutor, as_completed

# Suppress warnings
warnings.filterwarnings('ignore')

# Add current directory to path for imports
sys.path.append('.')

# Page configuration
st.set_page_config(
    page_title="NCIIPC Phishing Detection - PS-02",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
        background: linear-gradient(45deg, #1f77b4, #2e86ab);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        font-weight: bold;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #2e86ab;
        margin-top: 2rem;
        margin-bottom: 1rem;
        border-left: 4px solid #1f77b4;
        padding-left: 1rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 10px;
        border-left: 4px solid #1f77b4;
        margin: 0.5rem 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .warning-box {
        background-color: #fff3cd;
        border: 1px solid #ffeaa7;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .success-box {
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .info-box {
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        border-radius: 5px;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# CSE Configuration from the provided dataset
CSE_ENTITIES = {
    'State Bank of India (SBI)': {
        'sector': 'BFSI',
        'keywords': ['sbi', 'statebank', 'statebankofindia'],
        'whitelisted_domains': ['onlinesbi.sbi', 'sbi.co.in', 'sbicard.com', 
                               'yonobusiness.sbi', 'sbiepay.sbi', 'sbilife.co.in']
    },
    'ICICI Bank': {
        'sector': 'BFSI',
        'keywords': ['icici', 'icicibank'],
        'whitelisted_domains': ['icicibank.com', 'icicicareers.com', 'icicidirect.com',
                               'icicilombard.com', 'iciciprulife.com']
    },
    'HDFC Bank': {
        'sector': 'BFSI',
        'keywords': ['hdfc', 'hdfcbank'],
        'whitelisted_domains': ['hdfcbank.com', 'hdfc.com', 'hdfcergo.com', 'hdfclife.com']
    },
    'Punjab National Bank (PNB)': {
        'sector': 'BFSI',
        'keywords': ['pnb', 'punjabnationalbank'],
        'whitelisted_domains': ['pnbindia.in', 'netpnb.com']
    },
    'Bank of Baroda (BoB)': {
        'sector': 'BFSI',
        'keywords': ['bob', 'bankofbaroda'],
        'whitelisted_domains': ['bankofbaroda.in', 'bobibanking.com']
    },
    'National Informatics Centre (NIC)': {
        'sector': 'Government',
        'keywords': ['nic', 'nicgov', 'nationalinformatics'],
        'whitelisted_domains': ['nic.gov.in', 'email.gov.in', 'kavach.mail.gov.in',
                               'accounts.mgovcloud.in']
    },
    'Registrar General and Census Commissioner of India (RGCCI)': {
        'sector': 'Government',
        'keywords': ['rgcc', 'census', 'crsorgi'],
        'whitelisted_domains': ['dc.crsorgi.gov.in']
    },
    'Indian Railway Catering and Tourism Corporation (IRCTC)': {
        'sector': 'Transport',
        'keywords': ['irctc', 'indianrailway'],
        'whitelisted_domains': ['irctc.co.in', 'irctc.com']
    },
    'Airtel': {
        'sector': 'Telecom',
        'keywords': ['airtel'],
        'whitelisted_domains': ['airtel.in', 'airtel.com']
    },
    'Indian Oil Corporation Limited (IOCL)': {
        'sector': 'P&E',
        'keywords': ['iocl', 'indianoil'],
        'whitelisted_domains': ['iocl.com']
    }
}

class NCIIPCDashboard:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.load_model()
    
    def load_model(self):
        """Load the trained phishing detection model"""
        try:
            if os.path.exists('optimized_phishing_model.pkl'):
                artifacts = joblib.load('optimized_phishing_model.pkl')
                self.model = artifacts['model']
                self.scaler = artifacts['scaler']
                self.feature_names = artifacts['feature_names']
                st.sidebar.success("✅ Model loaded successfully!")
                return True
            else:
                st.sidebar.error("❌ Model file 'optimized_phishing_model.pkl' not found!")
                return False
        except Exception as e:
            st.sidebar.error(f"❌ Error loading model: {str(e)}")
            return False
    
    def extract_features_single(self, url):
        """Extract features for a single URL"""
        try:
            from feature_extraction import extract_all_features, Config
            Config.ENABLE_EXTERNAL_CALLS = False
            features = extract_all_features(url)
            return features, None
        except Exception as e:
            return self.get_default_features(), str(e)
    
    def get_default_features(self):
        """Return default feature values"""
        return {feature: 0 for feature in self.feature_names}
    
    def predict_batch(self, urls):
        """Make predictions for a batch of URLs"""
        features_list = []
        failed_urls = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_url = {executor.submit(self.extract_features_single, url): url for url in urls}
            
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    features, error = future.result()
                    if error:
                        failed_urls.append((url, error))
                    features_list.append(features)
                except Exception as e:
                    failed_urls.append((url, str(e)))
                    features_list.append(self.get_default_features())
        
        # Create DataFrame and make predictions
        test_df = pd.DataFrame(features_list)
        for col in self.feature_names:
            if col not in test_df.columns:
                test_df[col] = 0
        test_df = test_df[self.feature_names]
        
        X_scaled = self.scaler.transform(test_df)
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        return predictions, probabilities, failed_urls
    
    def classify_phishing(self, phishing_prob):
        """Classify based on NCIIPC thresholds"""
        if phishing_prob >= 0.7:
            return "Phishing", "high"
        elif phishing_prob >= 0.4:
            return "Suspected", "medium"
        else:
            return "Safe", "low"
    
    def match_cse_entity(self, domain):
        """Match domain to CSE entities - ONLY if it contains CSE keywords"""
        domain_clean = domain.lower().replace('www.', '').replace('https://', '').replace('http://', '').strip()
        
        # First check if it's a whitelisted domain (legitimate)
        for entity_name, entity_data in CSE_ENTITIES.items():
            if domain_clean in entity_data['whitelisted_domains']:
                return None  # It's legitimate, not phishing
        
        # Check for keyword matching in suspicious domains
        for entity_name, entity_data in CSE_ENTITIES.items():
            for keyword in entity_data['keywords']:
                if keyword in domain_clean:
                    # Additional check to avoid false positives
                    # Make sure the keyword is not just part of random words
                    keyword_pattern = r'\b' + re.escape(keyword) + r'\b'
                    if re.search(keyword_pattern, domain_clean):
                        return entity_name, entity_data['sector'], entity_data['whitelisted_domains'][0]
        
        return None

def get_hosting_info(domain):
    """Get hosting IP and ISP information"""
    try:
        ip = socket.gethostbyname(domain)
        # Simple country detection based on common TLDs
        country_map = {
            '.in': 'India', '.com': 'United States', '.org': 'United States',
            '.net': 'United States', '.edu': 'United States', '.gov': 'United States',
            '.uk': 'United Kingdom', '.de': 'Germany', '.fr': 'France',
            '.ca': 'Canada', '.au': 'Australia', '.jp': 'Japan'
        }
        
        country = 'Unknown'
        for tld, country_name in country_map.items():
            if domain.endswith(tld):
                country = country_name
                break
        
        return {
            'hosting_ip': ip,
            'hosting_isp': 'To be determined',  # Would require GeoIP database
            'hosting_country': country
        }
    except:
        return {'hosting_ip': '', 'hosting_isp': '', 'hosting_country': ''}

def get_dns_records(domain):
    """Get DNS records for the domain"""
    records = []
    try:
        # A records
        a_records = dns.resolver.resolve(domain, 'A')
        records.extend([f"A: {r.to_text()}" for r in a_records])
    except:
        pass
        
    try:
        # MX records
        mx_records = dns.resolver.resolve(domain, 'MX')
        records.extend([f"MX: {r.exchange} (Priority: {r.preference})" for r in mx_records])
    except:
        pass
        
    try:
        # NS records
        ns_records = dns.resolver.resolve(domain, 'NS')
        records.extend([f"NS: {r.to_text()}" for r in ns_records])
    except:
        pass
        
    return ' | '.join(records) if records else 'No DNS records found'

def get_domain_registration_info(domain):
    """Extract complete domain registration information"""
    try:
        domain_data = whois.whois(domain)
        hosting_info = get_hosting_info(domain)
        dns_info = get_dns_records(domain)
        
        # Handle registration date (could be list or single value)
        reg_date = ''
        if domain_data.creation_date:
            if isinstance(domain_data.creation_date, list):
                reg_date = domain_data.creation_date[0]
            else:
                reg_date = domain_data.creation_date
            
            if hasattr(reg_date, 'strftime'):
                reg_date = reg_date.strftime("%d-%m-%Y")
        
        # Handle name servers
        name_servers = ''
        if domain_data.name_servers:
            if isinstance(domain_data.name_servers, list):
                name_servers = '; '.join([str(ns) for ns in domain_data.name_servers])
            else:
                name_servers = str(domain_data.name_servers)
        
        info = {
            'registration_date': reg_date,
            'registrar': domain_data.registrar or 'Not available',
            'registrant': domain_data.name or domain_data.org or 'Not available',
            'country': domain_data.country or 'Not available',
            'name_servers': name_servers,
            'hosting_ip': hosting_info['hosting_ip'],
            'hosting_isp': hosting_info['hosting_isp'],
            'hosting_country': hosting_info['hosting_country'],
            'dns_records': dns_info
        }
        return info
        
    except Exception as e:
        # Return default values if WHOIS lookup fails
        hosting_info = get_hosting_info(domain)
        dns_info = get_dns_records(domain)
        
        return {
            'registration_date': 'Not available',
            'registrar': 'Not available',
            'registrant': 'Not available',
            'country': 'Not available',
            'name_servers': 'Not available',
            'hosting_ip': hosting_info['hosting_ip'],
            'hosting_isp': hosting_info['hosting_isp'],
            'hosting_country': hosting_info['hosting_country'],
            'dns_records': dns_info
        }

def create_nciipc_submission_format(submission_data, app_id):
    """Create the NCIIPC submission format with all required columns populated"""
    current_date = datetime.now().strftime("%d-%m-%Y")
    current_time = datetime.now().strftime("%H-%M-%S")
    
    submission_rows = []
    
    for i, domain_data in enumerate(submission_data, 1):
        # Extract complete domain registration info
        domain_info = get_domain_registration_info(domain_data['Domain'])
        
        row = {
            'S. No': i,
            'Sector': domain_data['CSE_Sector'],
            'Application_ID': app_id,
            'Source of detection': 'AI Model Prediction - NCIIPC PS-02',
            'Identified Phishing/Suspected Domain Name': domain_data['Domain'],
            'Corresponding CSE Domain Name': domain_data['Legitimate_Domain'],
            'Critical Sector Entity Name': domain_data['CSE_Entity'],
            'Phishing/Suspected Domains': domain_data['Classification'],
            'Domain Registration Date': domain_info['registration_date'],
            'Registrar Name': domain_info['registrar'],
            'Registrant Name or Registrant Organisation': domain_info['registrant'],
            'Registrant Country': domain_info['country'],
            'Name Servers': domain_info['name_servers'],
            'Hosting IP': domain_info['hosting_ip'],
            'Hosting ISP': domain_info['hosting_isp'],
            'Hosting Country': domain_info['hosting_country'],
            'DNS Records': domain_info['dns_records'],
            'Evidence file name': f"evidence_{domain_data['Domain'].replace('.', '_')}.txt",
            'Date of detection': current_date,
            'Time of detection': current_time,
            'Date of Post': '',  # Only for social media detections
            'Remarks': f"AI Model Confidence: {domain_data['Phishing_Probability']:.4f}; Risk Level: {domain_data.get('Risk_Level', 'Unknown')}; Target CSE: {domain_data['CSE_Entity']}"
        }
        submission_rows.append(row)
    
    return pd.DataFrame(submission_rows)

def generate_direct_submission(results, app_id, dashboard):
    """Generate direct submission file from batch processing results"""
    st.markdown("---")
    st.markdown("### 📤 Direct Submission Generation")
    
    results_df = pd.DataFrame(results)
    eligible_domains = results_df[results_df['Submission_Eligible'] == True]
    
    if not eligible_domains.empty:
        st.success(f"🎉 Found **{len(eligible_domains):,} eligible domains** for NCIIPC submission!")
        
        # Show quick summary
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Eligible Domains", len(eligible_domains))
        with col2:
            phishing_count = len(eligible_domains[eligible_domains['Risk_Level'] == 'high'])
            st.metric("🔴 Phishing", phishing_count)
        with col3:
            suspected_count = len(eligible_domains[eligible_domains['Risk_Level'] == 'medium'])
            st.metric("🟡 Suspected", suspected_count)
        
        # Show eligible domains preview
        st.markdown("#### 📋 Eligible Domains Preview")
        display_cols = ['Domain', 'Classification', 'Phishing_Probability', 'CSE_Entity', 'CSE_Sector']
        st.dataframe(
            eligible_domains[display_cols].sort_values('Phishing_Probability', ascending=False).head(10),
            use_container_width=True
        )
        
        if len(eligible_domains) > 10:
            st.info(f"Showing first 10 of {len(eligible_domains)} eligible domains. Full list will be in submission file.")
        
        # Generate submission file
        st.markdown("#### 🎯 Generating Submission File")
        
        with st.spinner("Collecting domain registration information and generating submission file..."):
            submission_data = []
            
            # Progress bar for domain info collection
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            for i, (_, domain_row) in enumerate(eligible_domains.iterrows()):
                status_text.text(f"Collecting domain information {i+1}/{len(eligible_domains)}...")
                
                submission_data.append({
                    'Domain': domain_row['Domain'],
                    'Classification': domain_row['Classification'],
                    'Phishing_Probability': domain_row['Phishing_Probability'],
                    'CSE_Entity': domain_row['CSE_Entity'],
                    'CSE_Sector': domain_row['CSE_Sector'],
                    'Legitimate_Domain': domain_row['Legitimate_Domain'],
                    'Risk_Level': domain_row['Risk_Level']
                })
                
                progress_bar.progress((i + 1) / len(eligible_domains))
            
            progress_bar.empty()
            status_text.text("✅ Domain information collected!")
            
            # Generate final submission file
            submission_df = create_nciipc_submission_format(submission_data, app_id)
            
            # Display final submission preview
            st.markdown("#### 📊 Final Submission Preview")
            st.dataframe(submission_df.head(10), use_container_width=True)
            
            if len(submission_df) > 10:
                st.info(f"Showing first 10 of {len(submission_df)} rows from submission file.")
            
            # Download buttons
            st.markdown("#### 💾 Download Submission Files")
            
            col1, col2, col3 = st.columns(3)
            
            with col1:
                # NCIIPC Submission File (Excel)
                excel_buffer = io.BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    submission_df.to_excel(writer, index=False, sheet_name='Submission')
                
                excel_buffer.seek(0)
                b64_excel = base64.b64encode(excel_buffer.read()).decode()
                filename = f"PS-02_{app_id}_Holdout_Submission_Set.xlsx"
                
                st.download_button(
                    label="📥 Download NCIIPC Submission (Excel)",
                    data=excel_buffer,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
            
            with col2:
                # CSV version for reference
                csv_data = submission_df.to_csv(index=False)
                b64_csv = base64.b64encode(csv_data.encode()).decode()
                csv_filename = f"PS-02_{app_id}_Submission_Reference.csv"
                
                st.download_button(
                    label="📊 Download Reference (CSV)",
                    data=csv_data,
                    file_name=csv_filename,
                    mime="text/csv",
                    use_container_width=True
                )
            
            with col3:
                # Eligible domains list
                eligible_csv = eligible_domains.to_csv(index=False)
                b64_eligible = base64.b64encode(eligible_csv.encode()).decode()
                eligible_filename = f"PS-02_{app_id}_Eligible_Domains.csv"
                
                st.download_button(
                    label="🎯 Download Eligible Domains",
                    data=eligible_csv,
                    file_name=eligible_filename,
                    mime="text/csv",
                    use_container_width=True
                )
            
            st.success(f"""
            ✅ **Submission Generation Complete!**
            
            **Generated Files:**
            - **`{filename}`** - Main NCIIPC submission file in Excel format
            - **`{csv_filename}`** - Reference file in CSV format  
            - **`{eligible_filename}`** - List of eligible domains only
            
            **Submission Summary:**
            - **Total Domains Processed:** {len(results_df):,}
            - **Eligible for Submission:** {len(eligible_domains):,}
            - **CSE Entities Targeted:** {eligible_domains['CSE_Entity'].nunique()}
            - **File Ready for NCIIPC Submission:** ✅
            """)
            
            # Show CSE distribution
            st.markdown("#### 📈 Submission Statistics")
            
            col1, col2 = st.columns(2)
            
            with col1:
                # CSE distribution
                cse_counts = eligible_domains['CSE_Entity'].value_counts()
                fig1 = px.bar(
                    x=cse_counts.values,
                    y=cse_counts.index,
                    orientation='h',
                    title="Domains by Targeted CSE Entity",
                    labels={'x': 'Number of Domains', 'y': 'CSE Entity'},
                    color=cse_counts.values,
                    color_continuous_scale='reds'
                )
                st.plotly_chart(fig1, use_container_width=True)
            
            with col2:
                # Risk distribution
                risk_counts = eligible_domains['Classification'].value_counts()
                fig2 = px.pie(
                    values=risk_counts.values,
                    names=risk_counts.index,
                    title="Classification Distribution",
                    color=risk_counts.index,
                    color_discrete_map={'Phishing': '#dc3545', 'Suspected': '#ffc107'}
                )
                st.plotly_chart(fig2, use_container_width=True)
    
    else:
        st.warning("""
        ⚠️ **No domains eligible for NCIIPC submission found.**
        
        This means no domains in your file meet both criteria:
        1. **Classification**: Phishing or Suspected (probability ≥ 0.4)
        2. **CSE Targeting**: Contains keywords matching Critical Sector Entities
        
        **Next Steps:**
        - Try processing a different dataset
        - Check if domains contain CSE keywords (SBI, ICICI, HDFC, NIC, IRCTC, etc.)
        - Use the regular analysis mode to see detailed results
        """)

def main():
    # Header with NCIIPC branding
    st.markdown("""
    <div style="text-align: center; padding: 1rem; background: linear-gradient(135deg, #1f77b4, #2e86ab); border-radius: 10px; margin-bottom: 2rem;">
        <h1 class="main-header">🛡️ NCIIPC AI Grand Challenge</h1>
        <h3 style="color: white; margin: 0;">Problem Statement PS-02: Phishing Detection for Critical Sector Entities</h3>
    </div>
    """, unsafe_allow_html=True)
    
    # Initialize dashboard
    dashboard = NCIIPCDashboard()
    
    if not dashboard.model:
        st.error("""
        ❌ Model not loaded. Please ensure:
        - 'optimized_phishing_model.pkl' is in the same directory
        - All required dependencies are installed
        - Feature extraction module is available
        """)
        st.stop()
    
    # Sidebar
    st.sidebar.title("NCIIPC PS-02 Dashboard")
    st.sidebar.markdown("---")
    
    app_mode = st.sidebar.selectbox(
        "Navigation",
        ["📊 Dashboard Overview", "🔍 Domain Analysis", "📁 Batch Processing", "📤 Submission Generator"]
    )
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Critical Sector Entities")
    for entity in CSE_ENTITIES:
        sector = CSE_ENTITIES[entity]['sector']
        st.sidebar.write(f"• **{entity}** ({sector})")
    
    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    **Submission Guidelines:**
    - Only Phishing/Suspected domains targeting 10 CSEs
    - Follow exact Excel format
    - No generic malicious domains
    - Clean, structured submission
    """)
    
    # Main content
    if app_mode == "📊 Dashboard Overview":
        show_dashboard_overview()
    elif app_mode == "🔍 Domain Analysis":
        show_domain_analysis(dashboard)
    elif app_mode == "📁 Batch Processing":
        show_batch_processing(dashboard)
    elif app_mode == "📤 Submission Generator":
        show_submission_generator(dashboard)

def show_dashboard_overview():
    st.markdown('<div class="sub-header">📊 Dashboard Overview</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("""
        ### Welcome to NCIIPC PS-02 Phishing Detection
        
        This dashboard is designed specifically for the **NCIIPC AI Grand Challenge Problem Statement PS-02**.
        
        **Key Objectives:**
        - Detect phishing and suspected domains targeting 10 Critical Sector Entities (CSEs)
        - Generate structured submissions in the required format
        - Ensure compliance with all competition guidelines
        
        **Supported Critical Sector Entities:**
        """)
        
        # Display CSE entities in a nice format
        sectors = {}
        for entity, data in CSE_ENTITIES.items():
            sector = data['sector']
            if sector not in sectors:
                sectors[sector] = []
            sectors[sector].append(entity)
        
        for sector, entities in sectors.items():
            with st.expander(f"🏛️ {sector} Sector ({len(entities)} entities)"):
                for entity in entities:
                    st.write(f"• **{entity}**")
                    domains = CSE_ENTITIES[entity]['whitelisted_domains']
                    if len(domains) <= 3:
                        st.write(f"  📍 {', '.join(domains)}")
                    else:
                        st.write(f"  📍 {', '.join(domains[:3])}... (+{len(domains)-3} more)")
    
    with col2:
        st.markdown("""
        <div class="metric-card">
            <h3>🚨 Important Notes</h3>
            <p><strong>Submission Rules:</strong></p>
            <ul>
            <li>Only CSE-targeted domains</li>
            <li>Phishing/Suspected only</li>
            <li>Strict format compliance</li>
            <li>No generic domains</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("""
        <div class="warning-box">
            <strong>⚠️ Disqualification Risks:</strong>
            <ul>
            <li>Irrelevant domains</li>
            <li>Format deviations</li>
            <li>Generic malicious domains</li>
            <li>Non-CSE targets</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)
    
    # Statistics
    st.markdown("---")
    st.markdown("### 📈 CSE Domain Statistics")
    
    col1, col2, col3, col4 = st.columns(4)
    
    total_entities = len(CSE_ENTITIES)
    total_domains = sum(len(data['whitelisted_domains']) for data in CSE_ENTITIES.values())
    sectors_count = len(set(data['sector'] for data in CSE_ENTITIES.values()))
    bfsi_count = sum(1 for data in CSE_ENTITIES.values() if data['sector'] == 'BFSI')
    
    with col1:
        st.metric("Total CSE Entities", total_entities)
    with col2:
        st.metric("Whitelisted Domains", total_domains)
    with col3:
        st.metric("Sectors Covered", sectors_count)
    with col4:
        st.metric("BFSI Entities", bfsi_count)
    
    # Sector distribution chart
    sector_data = []
    for entity, data in CSE_ENTITIES.items():
        sector_data.append({
            'Sector': data['sector'],
            'Entity': entity,
            'Domain Count': len(data['whitelisted_domains'])
        })
    
    sector_df = pd.DataFrame(sector_data)
    fig = px.sunburst(
        sector_df, 
        path=['Sector', 'Entity'], 
        values='Domain Count',
        title="CSE Entity Distribution by Sector",
        color='Sector'
    )
    st.plotly_chart(fig, use_container_width=True)

def show_domain_analysis(dashboard):
    st.markdown('<div class="sub-header">🔍 Single Domain Analysis</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        domain_input = st.text_input(
            "Enter domain to analyze:",
            placeholder="example.com or www.example.com",
            help="Enter domain name without http:// or https://"
        )
    
    with col2:
        st.write("")
        st.write("")
        analyze_btn = st.button("Analyze Domain", type="primary", use_container_width=True)
    
    if analyze_btn and domain_input:
        # Preprocess domain
        domain_clean = domain_input.lower().replace('www.', '').strip()
        test_url = f"https://{domain_clean}"
        
        with st.spinner("Analyzing domain..."):
            predictions, probabilities, failed_urls = dashboard.predict_batch([test_url])
            
            if predictions is not None:
                phishing_prob = probabilities[0][1]  # Assuming second column is phishing
                classification, risk_level = dashboard.classify_phishing(phishing_prob)
                cse_match = dashboard.match_cse_entity(domain_clean)
                
                # Display results
                st.markdown("---")
                st.markdown("### 🔍 Analysis Results")
                
                # Main risk card
                risk_color = "#dc3545" if risk_level == "high" else "#ffc107" if risk_level == "medium" else "#28a745"
                risk_icon = "🔴" if risk_level == "high" else "🟡" if risk_level == "medium" else "🟢"
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.markdown(f"""
                    <div style="text-align: center; padding: 2rem; border-radius: 10px; background-color: {risk_color}20; border: 2px solid {risk_color};">
                        <h1 style="color: {risk_color}; margin: 0;">{risk_icon} {classification}</h1>
                        <h3 style="color: {risk_color}; margin: 0;">Risk Level: {risk_level.upper()}</h3>
                        <p style="font-size: 1.2rem; margin: 0.5rem 0;">Phishing Probability: {phishing_prob:.3f}</p>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    # CSE matching result - ONLY show if there's a match
                    if cse_match:
                        entity_name, sector, legit_domain = cse_match
                        st.markdown(f"""
                        <div class="success-box">
                            <h4>🎯 CSE Match Found</h4>
                            <p><strong>Entity:</strong> {entity_name}</p>
                            <p><strong>Sector:</strong> {sector}</p>
                            <p><strong>Legitimate Domain:</strong> {legit_domain}</p>
                        </div>
                        """, unsafe_allow_html=True)
                    else:
                        # Check if it's a whitelisted domain
                        is_whitelisted = False
                        for entity_data in CSE_ENTITIES.values():
                            if domain_clean in entity_data['whitelisted_domains']:
                                is_whitelisted = True
                                break
                        
                        if is_whitelisted:
                            st.markdown("""
                            <div class="info-box">
                                <h4>✅ Legitimate CSE Domain</h4>
                                <p>This is a whitelisted legitimate domain of a CSE entity</p>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.markdown("""
                            <div class="warning-box">
                                <h4>🌐 Generic Domain</h4>
                                <p>This domain does not target any Critical Sector Entity</p>
                                <p><em>Not eligible for NCIIPC submission</em></p>
                            </div>
                            """, unsafe_allow_html=True)
                
                # Probability gauge
                st.markdown("### 📊 Risk Assessment")
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = phishing_prob * 100,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Phishing Confidence Score"},
                    gauge = {
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgreen"},
                            {'range': [40, 70], 'color': "yellow"},
                            {'range': [70, 100], 'color': "red"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': phishing_prob * 100
                        }
                    }
                ))
                fig.update_layout(height=300)
                st.plotly_chart(fig, use_container_width=True)
                
                # Domain Information
                st.markdown("### 📋 Domain Registration Information")
                domain_info = get_domain_registration_info(domain_clean)
                
                info_col1, info_col2 = st.columns(2)
                
                with info_col1:
                    st.write("**Registration Details:**")
                    st.write(f"- **Registrar:** {domain_info['registrar']}")
                    st.write(f"- **Registration Date:** {domain_info['registration_date']}")
                    st.write(f"- **Registrant:** {domain_info['registrant']}")
                    st.write(f"- **Country:** {domain_info['country']}")
                
                with info_col2:
                    st.write("**Hosting Details:**")
                    st.write(f"- **Hosting IP:** {domain_info['hosting_ip']}")
                    st.write(f"- **Hosting Country:** {domain_info['hosting_country']}")
                    st.write(f"- **Name Servers:** {domain_info['name_servers'][:100]}..." if len(domain_info['name_servers']) > 100 else f"- **Name Servers:** {domain_info['name_servers']}")
                
                # DNS Records
                st.write("**DNS Records:**")
                st.write(domain_info['dns_records'])
                
                # Submission eligibility
                if risk_level in ["high", "medium"] and cse_match:
                    st.markdown(f"""
                    <div class="success-box">
                        <h3>✅ Eligible for Submission</h3>
                        <p>This domain meets NCIIPC submission criteria:</p>
                        <ul>
                        <li>✅ Classification: {classification}</li>
                        <li>✅ Targets CSE: {cse_match[0]}</li>
                        <li>✅ Sector: {cse_match[1]}</li>
                        </ul>
                    </div>
                    """, unsafe_allow_html=True)
                elif risk_level in ["high", "medium"] and not cse_match:
                    st.markdown(f"""
                    <div class="warning-box">
                        <h3>⚠️ Not Submission Eligible</h3>
                        <p>Domain is <strong>{classification}</strong> but does not target any Critical Sector Entity.</p>
                        <p><em>Only CSE-targeted phishing/suspected domains are eligible for submission</em></p>
                    </div>
                    """, unsafe_allow_html=True)

def show_batch_processing(dashboard):
    st.markdown('<div class="sub-header">📁 Batch Domain Processing</div>', unsafe_allow_html=True)
    
    st.markdown("""
    **Process multiple domains for NCIIPC submission analysis.**
    Upload a file containing domains to analyze the ENTIRE dataset and generate submission files directly.
    """)
    
    # File upload section
    uploaded_file = st.file_uploader(
        "Upload CSV or Excel file with domains",
        type=['csv', 'xlsx'],
        help="File should contain a column with domain names. The ENTIRE file will be processed."
    )
    
    domains_to_process = []
    domain_column = None
    
    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith('.csv'):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)
            
            st.success(f"✅ File loaded successfully! Found {len(df):,} rows")
            
            # Show data preview
            st.markdown("#### 📋 Data Preview")
            st.dataframe(df.head(), use_container_width=True)
            st.write(f"**Columns detected:** {list(df.columns)}")
            
            # Auto-detect domain column
            possible_columns = ['domain', 'domain_name', 'url', 'host', 'hostname', 'website']
            
            for col in possible_columns:
                if col in df.columns:
                    domain_column = col
                    break
            
            if domain_column is None and len(df.columns) > 0:
                domain_column = df.columns[0]
                st.info(f"Using first column '{domain_column}' as domain source")
            
            if domain_column:
                # Extract ALL domains (no sampling)
                raw_domains = df[domain_column].dropna().astype(str).tolist()
                domains_to_process = [domain.lower().replace('www.', '').strip() for domain in raw_domains]
                domains_to_process = [domain for domain in domains_to_process if '.' in domain and len(domain) > 3]
                
                st.info(f"📊 Ready to process **ALL {len(domains_to_process):,} valid domains** from the file")
                
                # Show processing warning for large files
                if len(domains_to_process) > 1000:
                    st.warning(f"""
                    ⚠️ **Large Dataset Warning**
                    
                    You are about to process **{len(domains_to_process):,} domains**. 
                    This may take several minutes depending on your system.
                    
                    Estimated time: **{len(domains_to_process) / 10:.0f} - {len(domains_to_process) / 5:.0f} seconds**
                    """)
            
        except Exception as e:
            st.error(f"❌ Error reading file: {str(e)}")
    
    # Application ID input for direct submission generation
    st.markdown("---")
    st.markdown("### 📝 Submission Configuration")
    
    app_id = st.text_input(
        "Application ID for submission file:",
        placeholder="AIGR-XXXXXX",
        help="Enter your NCIIPC Application ID for generating the submission file",
        key="batch_app_id"
    )
    
    # Processing section
    if domains_to_process and app_id:
        st.markdown("### ⚙️ Processing Options")
        
        col1, col2, col3 = st.columns([2, 1, 1])
        
        with col1:
            st.info(f"**Processing entire dataset:** {len(domains_to_process):,} domains")
            st.write("**Direct submission generation available:**")
            st.write("• Phishing classification & CSE matching")
            st.write("• Complete domain registration information") 
            st.write("• Automatic NCIIPC format compliance")
            st.write("• Direct download of submission file")
        
        with col2:
            st.write("")
            st.write("")
            process_btn = st.button("🚀 PROCESS & ANALYZE", type="primary", use_container_width=True)
        
        with col3:
            st.write("")
            st.write("")
            direct_submission_btn = st.button("📤 DIRECT SUBMISSION", type="secondary", use_container_width=True,
                                            help="Process domains and generate submission file directly")
        
        if process_btn or direct_submission_btn:
            # Process ALL domains (no sampling)
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            results = []
            batch_size = 50  # Smaller batches for better progress tracking
            total_batches = (len(domains_to_process) + batch_size - 1) // batch_size
            
            for batch_idx in range(total_batches):
                start_idx = batch_idx * batch_size
                end_idx = min(start_idx + batch_size, len(domains_to_process))
                batch_domains = domains_to_process[start_idx:end_idx]
                
                status_text.text(f"Processing batch {batch_idx + 1}/{total_batches} ({end_idx}/{len(domains_to_process)} domains)...")
                
                # Convert to URLs for feature extraction
                batch_urls = [f"https://{domain}" for domain in batch_domains]
                predictions, probabilities, failed_urls = dashboard.predict_batch(batch_urls)
                
                if predictions is not None:
                    for i, domain in enumerate(batch_domains):
                        if i < len(predictions):
                            phishing_prob = probabilities[i][1]
                            classification, risk_level = dashboard.classify_phishing(phishing_prob)
                            cse_match = dashboard.match_cse_entity(domain)
                            
                            result = {
                                'Domain': domain,
                                'Classification': classification,
                                'Risk_Level': risk_level,
                                'Phishing_Probability': phishing_prob,
                                'CSE_Entity': cse_match[0] if cse_match else 'None',
                                'CSE_Sector': cse_match[1] if cse_match else 'None',
                                'Legitimate_Domain': cse_match[2] if cse_match else 'None',
                                'Submission_Eligible': (risk_level in ["high", "medium"] and cse_match is not None)
                            }
                            results.append(result)
                
                progress_bar.progress((batch_idx + 1) / total_batches)
            
            progress_bar.empty()
            status_text.text("✅ Analysis completed!")
            
            # Display results
            if results:
                if direct_submission_btn:
                    # Direct submission generation
                    generate_direct_submission(results, app_id, dashboard)
                else:
                    # Regular analysis display
                    display_batch_results(results, len(domains_to_process), app_id, dashboard)

def display_batch_results(results, total_domains_processed, app_id=None, dashboard=None):
    """Display batch processing results with enhanced download options"""
    results_df = pd.DataFrame(results)
    
    st.markdown("---")
    st.markdown("### 📈 Complete Analysis Results")
    
    # Summary statistics
    total_domains = len(results_df)
    phishing_count = len(results_df[results_df['Risk_Level'] == 'high'])
    suspected_count = len(results_df[results_df['Risk_Level'] == 'medium'])
    safe_count = len(results_df[results_df['Risk_Level'] == 'low'])
    cse_targeted_count = len(results_df[results_df['CSE_Entity'] != 'None'])
    eligible_count = len(results_df[results_df['Submission_Eligible'] == True])
    
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Processed", f"{total_domains:,}")
    with col2:
        st.metric("🔴 Phishing", f"{phishing_count:,}")
    with col3:
        st.metric("🟡 Suspected", f"{suspected_count:,}")
    with col4:
        st.metric("🎯 CSE-Targeted", f"{cse_targeted_count:,}")
    with col5:
        st.metric("✅ Eligible", f"{eligible_count:,}")
    
    # Quick submission generation for eligible domains
    eligible_domains = results_df[results_df['Submission_Eligible'] == True]
    
    if not eligible_domains.empty and app_id:
        st.markdown("#### 🚀 Quick Submission Generation")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            st.info(f"**{len(eligible_domains):,} domains** are eligible for NCIIPC submission")
            st.write("Generate submission file directly with the collected data")
        
        with col2:
            if st.button("⚡ Generate Quick Submission", type="primary", use_container_width=True):
                generate_direct_submission(results, app_id, dashboard)
    
    # CSE distribution - ONLY show for domains that actually match CSEs
    cse_targeted = results_df[results_df['CSE_Entity'] != 'None']
    
    if not cse_targeted.empty:
        st.markdown("#### 🎯 CSE-Targeted Domains Analysis")
        
        col1, col2 = st.columns(2)
        
        with col1:
            # CSE entity distribution
            cse_counts = cse_targeted['CSE_Entity'].value_counts()
            fig1 = px.bar(
                x=cse_counts.values,
                y=cse_counts.index,
                orientation='h',
                title="Domains by Targeted CSE Entity",
                labels={'x': 'Number of Domains', 'y': 'CSE Entity'},
                color=cse_counts.values,
                color_continuous_scale='reds'
            )
            st.plotly_chart(fig1, use_container_width=True)
        
        with col2:
            # Risk distribution for CSE-targeted domains
            risk_counts = cse_targeted['Risk_Level'].value_counts()
            fig2 = px.pie(
                values=risk_counts.values,
                names=risk_counts.index,
                title="Risk Distribution for CSE-Targeted Domains",
                color=risk_counts.index,
                color_discrete_map={'high': '#dc3545', 'medium': '#ffc107', 'low': '#28a745'}
            )
            st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No CSE-targeted domains found in the entire dataset.")
    
    # Eligible domains for submission
    if not eligible_domains.empty:
        st.markdown("#### 📋 Eligible Domains for NCIIPC Submission")
        
        st.info(f"Found **{len(eligible_domains):,} domains** that meet all NCIIPC submission criteria")
        
        display_cols = ['Domain', 'Classification', 'Phishing_Probability', 'CSE_Entity', 'CSE_Sector']
        st.dataframe(
            eligible_domains[display_cols].sort_values('Phishing_Probability', ascending=False),
            use_container_width=True,
            height=400
        )
        
        # Show statistics about eligible domains
        st.markdown("##### 📊 Eligible Domains Statistics")
        eligible_stats = eligible_domains['CSE_Entity'].value_counts()
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**By CSE Entity:**")
            for entity, count in eligible_stats.items():
                st.write(f"• {entity}: {count} domains")
        
        with col2:
            st.write("**By Classification:**")
            class_stats = eligible_domains['Classification'].value_counts()
            for cls, count in class_stats.items():
                st.write(f"• {cls}: {count} domains")
        
        # Download options
        st.markdown("#### 💾 Download Results")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            # Full results
            csv_full = results_df.to_csv(index=False)
            st.download_button(
                label="📥 Download Complete Analysis",
                data=csv_full,
                file_name="nciipc_complete_analysis.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col2:
            # Eligible domains only
            csv_eligible = eligible_domains.to_csv(index=False)
            st.download_button(
                label="🚨 Download Eligible Domains",
                data=csv_eligible,
                file_name="nciipc_eligible_domains.csv",
                mime="text/csv",
                use_container_width=True
            )
        
        with col3:
            # CSE-targeted only
            csv_cse = cse_targeted.to_csv(index=False)
            st.download_button(
                label="🎯 Download CSE-Targeted",
                data=csv_cse,
                file_name="nciipc_cse_targeted.csv",
                mime="text/csv",
                use_container_width=True
            )
    else:
        st.warning("""
        ⚠️ **No domains eligible for NCIIPC submission found.**
        
        This means no domains in your file meet both criteria:
        1. **Classification**: Phishing or Suspected (probability ≥ 0.4)
        2. **CSE Targeting**: Contains keywords matching Critical Sector Entities
        
        Eligible domains must target specific CSEs like SBI, ICICI, HDFC, NIC, IRCTC, etc.
        """)

def show_submission_generator(dashboard):
    st.markdown('<div class="sub-header">📤 NCIIPC Submission Generator</div>', unsafe_allow_html=True)
    
    st.markdown("""
    **Generate the final submission file in the required NCIIPC format.**
    
    This tool helps you create the proper `PS-02_<Application_ID>_Holdout_Submission_Set.xlsx` file
    with all required columns and formatting.
    """)
    
    # Application ID input
    app_id = st.text_input(
        "Application ID:",
        placeholder="AIGR-XXXXXX",
        help="Enter your NCIIPC Application ID"
    )
    
    # Load existing results or process new domains
    st.markdown("### 📁 Input Data Source")
    
    input_source = st.radio(
        "Select data source:",
        ["Upload Analysis Results", "Process New Domains"],
        horizontal=True
    )
    
    submission_data = []
    
    if input_source == "Upload Analysis Results":
        results_file = st.file_uploader(
            "Upload previous analysis results (CSV):",
            type=['csv'],
            help="Upload a CSV file from the Batch Processing results"
        )
        
        if results_file is not None:
            try:
                results_df = pd.read_csv(results_file)
                eligible_domains = results_df[results_df['Submission_Eligible'] == True]
                
                if not eligible_domains.empty:
                    submission_data = eligible_domains.to_dict('records')
                    st.success(f"✅ Loaded {len(submission_data)} eligible domains for submission")
                else:
                    st.warning("No eligible domains found in the uploaded file.")
            
            except Exception as e:
                st.error(f"❌ Error reading results file: {str(e)}")
    
    else:  # Process New Domains
        domain_input = st.text_area(
            "Enter eligible domains for submission (one per line):",
            height=200,
            placeholder="Enter only Phishing/Suspected domains that target CSE entities...",
            help="Only include domains that are classified as Phishing/Suspected AND target CSE entities"
        )
        
        if domain_input and app_id:
            domains = [line.strip() for line in domain_input.split('\n') if line.strip()]
            
            if domains:
                with st.spinner("Validating domains..."):
                    validated_domains = []
                    
                    for domain in domains:
                        domain_clean = domain.lower().replace('www.', '').strip()
                        cse_match = dashboard.match_cse_entity(domain_clean)
                        
                        if cse_match:
                            # Quick classification
                            test_url = f"https://{domain_clean}"
                            predictions, probabilities, _ = dashboard.predict_batch([test_url])
                            
                            if predictions is not None:
                                phishing_prob = probabilities[0][1]
                                classification, risk_level = dashboard.classify_phishing(phishing_prob)
                                
                                if risk_level in ["high", "medium"]:
                                    validated_domains.append({
                                        'Domain': domain_clean,
                                        'Classification': classification,
                                        'Phishing_Probability': phishing_prob,
                                        'CSE_Entity': cse_match[0],
                                        'CSE_Sector': cse_match[1],
                                        'Legitimate_Domain': cse_match[2],
                                        'Risk_Level': risk_level
                                    })
                    
                    submission_data = validated_domains
                    st.success(f"✅ Validated {len(submission_data)} domains for submission")
    
    # Generate submission file
    if submission_data and app_id:
        st.markdown("---")
        st.markdown("### 🎯 Generate Submission File")
        
        # Show submission preview
        st.markdown("#### 📋 Submission Preview")
        preview_df = pd.DataFrame(submission_data)
        st.dataframe(preview_df, use_container_width=True)
        
        # Generate NCIIPC format
        if st.button("🔄 Generate NCIIPC Submission File", type="primary"):
            with st.spinner("Generating submission file with complete domain information..."):
                submission_df = create_nciipc_submission_format(submission_data, app_id)
                
                # Display final submission
                st.markdown("#### 📊 Final Submission Data")
                st.dataframe(submission_df, use_container_width=True)
                
                # Download button
                excel_buffer = io.BytesIO()
                with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                    submission_df.to_excel(writer, index=False, sheet_name='Submission')
                
                excel_buffer.seek(0)
                filename = f"PS-02_{app_id}_Holdout_Submission_Set.xlsx"
                
                st.download_button(
                    label="📥 Download NCIIPC Submission File",
                    data=excel_buffer,
                    file_name=filename,
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
                
                st.success("""
                ✅ Submission file generated successfully!
                
                **Next Steps:**
                1. Review the downloaded Excel file
                2. Ensure all required columns are present
                3. Verify domain classifications
                4. Submit to FITT as per instructions
                
                **File includes all required NCIIPC columns:**
                - S. No, Sector, Application_ID
                - Source of detection, Domain names
                - CSE Entity information
                - Complete domain registration details
                - Hosting information
                - DNS records
                - Detection dates and evidence
                """)

if __name__ == "__main__":
    main()