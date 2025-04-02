import json
import pandas as pd
from functions import *

favicon_url = "https://raw.githubusercontent.com/XerxesViper/dns-analyser/refs/heads/main/favicon.ico"
preview_image_url = "https://github.com/XerxesViper/dns-analyser/blob/5e2c4f9f2692918547bdabc8bcd919e30f0fac69/preview.jpg"

page_url = "https://www.dnsanalyser.report/"
page_title = "DNSAnalyser Report | Free DNS & SSL Security Check"
page_description = "Instantly check your domain's DNS security score (SPF, DMARC, DNSSEC, CAA), SSL certificate, and common vulnerabilities. Get your free report!"

st.set_page_config(
    page_title=page_title,
    page_icon=favicon_url,
    layout="wide"
)

st.markdown(f"""
    <meta property="og:title" content="{page_title}">
    <meta property="og:description" content="{page_description}">
    <meta property="og:image" content="{preview_image_url}">
    <meta property="og:url" content="{page_url}">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="{page_title}">
    <meta name="twitter:description" content="{page_description}">
    <meta name="twitter:image" content="{preview_image_url}">
""", unsafe_allow_html=True)

st.markdown(f'<meta name="description" content="{page_description}">', unsafe_allow_html=True)

hide_menu_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
.stDeployButton {display:none;}
#stDecoration {display:none;}
</style>
"""
st.markdown(hide_menu_style, unsafe_allow_html=True)

st.title("DNS Security Analyzer & Domain Health Check")
st.markdown("""
 Perform a deep dive into your domain's security configuration.
 This tool analyzes A, AAAA, MX, TXT, SOA, NS, CNAME, CAA records, validates SPF, DMARC, DNSSEC, checks SSL/TLS certificates, and tests for zone transfer vulnerabilities.
 Receive a detailed security score and clear guidance. Enter your domain to begin.
""")

st.info("""
**Note:** If you receive unexpected results or errors, please consider temporarily disabling any VPN 
or proxy services you may be using, as they can sometimes interfere with DNS lookups.
""", icon="ℹ️")

with st.expander("Understanding Your DNS Security Score"):
    st.markdown("""
    ### How the DNS Security Score is Calculated

    Your domain's DNS security score is based on several key factors:

    | Factor | Impact | Why It Matters |
    |--------|--------|----------------|
    | SPF Record | -15 points if missing | Prevents email spoofing |
    | DMARC Record | -15 points if missing | Controls email authentication policy |
    | DNSSEC | -10 points if not implemented | Protects against DNS spoofing |
    | Zone Transfer | -25 points if allowed | Prevents information disclosure |
    | Multiple SPF Records | -10 points | Causes email delivery issues |
    | SPF with +all | -20 points | Allows anyone to send as your domain |
    | DMARC with p=none | -10 points | Only monitors but doesn't protect |

    A score of 90-100 indicates excellent DNS security configuration.\n
    A score of 70-89 indicates good security with some improvements needed.\n
    A score below 70 indicates significant security issues that should be addressed.
    """)

# --- Add the Cache Toggle Checkbox ---
force_refresh = st.checkbox("Force new DNS request (ignore cache)", value=True, key="force_refresh_toggle")

# --- Domain Input Section ---
domain_name = st.text_input("Domain Name:", placeholder="example.com OR www.example.com", key="domain_input")

# Initialize session state if not already done
if 'results' not in st.session_state:
    st.session_state.results = None
if 'domain' not in st.session_state:
    st.session_state.domain = ""
if 'show_results' not in st.session_state:
    st.session_state.show_results = False

# Main app logic
if st.button("Analyze", key="analyze_button"):
    if domain_name:
        sanitized_domain = sanitize_domain(domain_name)
        if sanitized_domain:
            st.info(f"Analyzing domain: {sanitized_domain}")
            # Decide whether to use cache based on checkbox
            if force_refresh:
                # Call the function WITHOUT the cache decorator
                results = analyze_domain_fresh(sanitized_domain)
            else:
                # Call the function WITH the cache decorator
                results = analyze_domain_cached(sanitized_domain)

            # Store results in session state for display
            st.session_state.domain = sanitized_domain
            st.session_state.results = results
            st.session_state.show_results = True
        else:
            st.error("Invalid domain name format. Please enter a valid domain like 'example.com'")
            st.session_state.show_results = False  # Hide previous results
    else:
        st.warning("Please enter a domain name first.")
        st.session_state.show_results = False  # Hide previous results

if st.session_state.show_results and st.session_state.results:
    st.markdown("---")

    # --- Score Summary Area ---
    with st.container():  # Use a container for the summary
        st.subheader(f"Analysis Summary for: {st.session_state.domain}")  # Use subheader

        score = st.session_state.results["score"]["score"]
        score_delta = None  # Placeholder if you add history later

        # Use columns for score metric and text summary
        col1, col2 = st.columns([1, 3])
        with col1:
            st.metric(label="Overall DNS Security Score", value=f"{score}/100", delta=score_delta)
        with col2:
            if score >= 90:
                st.success("✅ Excellent Configuration: Your DNS settings appear secure and well-configured.")
            elif score >= 70:
                st.warning(f"⚠️ Good Configuration: Some improvements recommended. See tabs below for details.")
            elif not domain_exists(st.session_state.domain):
                st.error(f"❌ Domain may not exist or could not be found.")
            else:
                st.error(f"❌ Needs Attention: Significant issues found. Please review the details in the tabs below.")

            # Display score deductions clearly
            if st.session_state.results["score"]["reasons"]:
                st.write("**Score Deductions:**")
                for reason in st.session_state.results["score"]["reasons"]:
                    st.caption(f"- {reason}")  # Use caption for less emphasis

                # --- Add Download Buttons ---
                st.markdown("**Download Results:**")
                col_dl1, col_dl2, col_dl_spacer = st.columns([1, 1, 2])  # Add spacer column

                results_data = st.session_state.results
                # Sanitize domain name for use in filename
                domain_file_part = re.sub(r'[^a-zA-Z0-9_-]', '_', st.session_state.domain)

                # JSON Download
                try:
                    # Use default=str to handle potential non-serializable types like datetime
                    json_string = json.dumps(results_data, indent=2, default=str)
                    with col_dl1:
                        st.download_button(
                            label="📥 Download JSON (Full Details)",
                            data=json_string,
                            file_name=f"{domain_file_part}_dns_analysis.json",
                            mime="application/json",
                            key="download_json"
                        )
                except Exception as e:
                    with col_dl1:
                        st.caption(f"Error generating JSON: {e}")

                # CSV Download (Summary)
                try:
                    # Flatten data for CSV - select key fields
                    flat_data = {
                        "Domain": st.session_state.domain,
                        "Score": results_data.get("score", {}).get("score", "N/A"),
                        "SPF_Status": results_data.get("spf", {}).get("status", "N/A"),
                        "DMARC_Status": results_data.get("dmarc", {}).get("status", "N/A"),
                        "DNSSEC_Status": results_data.get("dnssec", {}).get("status", "N/A"),
                        "CAA_Status": results_data.get("caa", {}).get("status", "N/A"),
                        "ZoneTransfer_Status": results_data.get("zone_transfer", {}).get("status", "N/A"),
                        "SSL_Status": results_data.get("ssl_tls", {}).get("status", "N/A"),
                        "SSL_Expiry_DaysLeft": results_data.get("ssl_tls", {}).get("details", {}).get("days_left", "N/A"),
                        "Analysis_Timestamp": results_data.get("timestamp", "N/A")
                    }
                    df = pd.DataFrame([flat_data])
                    # Use utf-8-sig encoding to handle potential BOM issues in Excel
                    csv_string = df.to_csv(index=False, encoding='utf-8-sig')
                    with col_dl2:
                        st.download_button(
                            label="📥 Download CSV (Summary)",
                            data=csv_string,
                            file_name=f"{domain_file_part}_dns_summary.csv",
                            mime="text/csv",
                            key="download_csv"
                        )
                except ImportError:
                    with col_dl2:
                        st.caption("Error: Pandas library not installed.")
                except Exception as e:
                    with col_dl2:
                        st.caption(f"Error generating CSV: {e}")
                # --- End Download Buttons ---

    st.markdown("---")  # Divider

    # --- Detailed Results Tabs ---
    st.subheader("Detailed Checks")
    display_results(st.session_state.domain, st.session_state.results)  # Call display with stored results

# Add footer with information
st.markdown("---")
st.markdown("""
**About this tool:**  
This DNS Security Analyzer checks for common DNS misconfigurations and security issues.
It is intended for educational purposes and security assessments.

---

<div style="display: flex; justify-content: start; gap: 20px; flex-wrap: wrap;">
    <div>Developed by:- <a href="https://www.xerxesviper.fyi" target="_blank">XerxesViper</a></div>
    <div><a href="https://twitter.com/XerxesViper" target="_blank">Twitter</a></div>
    <div><a href="https://github.com/XerxesViper" target="_blank">GitHub</a></div>
</div>
<div style="margin-top: 10px;">
    For suggestions or comments, please contact me at: <a href="mailto:xerxesviper@025609.xyz">xerxesviper@025609.xyz</a>
</div>
""", unsafe_allow_html=True)
