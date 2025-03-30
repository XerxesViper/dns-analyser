import streamlit as st
import dns.resolver
import dns.zone
import dns.query
import socket
import time
from datetime import datetime
import re

# Set page configuration
st.set_page_config(
    page_title="DNS Security Analyzer",
    page_icon="🔒",
    layout="wide"
)

hide_menu_style = """
<style>
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
.stDeployButton {display:none;}
#stDecoration {display:none;}
</style>
"""
st.markdown(hide_menu_style, unsafe_allow_html=True)

# Title and description
st.title("DNS Security Analyzer")
st.markdown("""
This tool analyzes DNS configurations to identify security issues, misconfigurations, 
and vulnerabilities in DNS settings. Enter a domain name below to begin.
""")

# Add this near the top of your app
st.info("""
**Note:** If you receive unexpected results or errors, please consider temporarily disabling any VPN 
or proxy services you may be using, as they can sometimes interfere with DNS lookups.
""", icon="ℹ️")

# Input for domain name
domain_name = st.text_input("Domain Name:", placeholder="example.com OR www.example.com")


def domain_exists(domain):
    try:
        # Try to resolve the domain's A record
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Use reliable public DNS
        resolver.resolve(domain, 'A')
        return True
    except dns.resolver.NXDOMAIN:
        # NXDOMAIN specifically means the domain doesn't exist
        return False
    except Exception:
        # For other errors, we'll still try to analyze
        # (could be just that A or AAAA (because of IPv6) records don't exist but the domain does)
        return True


def sanitize_domain(input_domain):
    """Sanitize and validate a domain name input."""
    if not input_domain:
        return None

    # Strip whitespace and convert to lowercase
    domain = input_domain.strip().lower()

    # Remove protocol prefixes
    if "://" in domain:
        domain = domain.split("://")[1]

    # Remove paths, query parameters, and fragments
    if "/" in domain:
        domain = domain.split("/")[0]

    # Remove port if specified
    if ":" in domain:
        domain = domain.split(":")[0]

    # Remove leading www. if present
    if domain.startswith("www."):
        domain = domain[4:]

    # Validate domain format using regex
    domain_pattern = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    if not re.match(domain_pattern, domain):
        return None

    # Additional security checks
    # Prevent command injection by ensuring no shell special characters
    if any(c in domain for c in ';|&`$()"\'\\'):
        return None

    # Limit length to prevent DoS attacks
    if len(domain) > 253:  # Max domain length per DNS specs
        return None

    # Ensure each label is valid
    labels = domain.split('.')
    if any(len(label) > 63 for label in labels):  # Max label length per DNS specs
        return None

    # Ensure TLD exists (basic check)
    if len(labels[-1]) < 2:
        return None

    return domain


# Function to check basic DNS records
def check_basic_dns(domain):
    results = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']

    st.write("Checking Basic DNS Records")

    # Create a Streamlit progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()

    for i, record_type in enumerate(record_types):
        # Update progress bar and status text
        progress = i / len(record_types)
        progress_bar.progress(progress)
        status_text.text(f"Checking {record_type} records...")

        try:
            answers = dns.resolver.resolve(domain, record_type)
            results[record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            results[record_type] = [f"Error: {str(e)}"]

    # Complete the progress bar
    progress_bar.progress(1.0)
    status_text.text("DNS record checks complete!")

    # Give a moment to see the completion message
    time.sleep(0.5)

    # Clear the status indicators
    status_text.empty()
    progress_bar.empty()

    return results


# Function to check SPF record
def check_spf(txt_records):
    spf_records = []

    st.write("Checking SPF Records")

    for record in txt_records:
        if record.startswith('"v=spf1') or record.startswith('v=spf1'):
            spf_records.append(record)

    if not spf_records:
        return {
            "status": "warning",
            "message": "No SPF record found. This may allow email spoofing.",
            "recommendation": "Add an SPF record to specify authorized mail servers."
        }
    elif len(spf_records) > 1:
        return {
            "status": "error",
            "message": "Multiple SPF records found. This is invalid and may cause email delivery issues.",
            "recommendation": "Consolidate into a single SPF record."
        }
    else:
        # Basic validation of SPF record
        spf = spf_records[0]
        if "~all" in spf or "-all" in spf:
            return {
                "status": "success",
                "message": "Valid SPF record with appropriate restrictions found.",
                "record": spf
            }
        elif "+all" in spf:
            return {
                "status": "error",
                "message": "SPF record uses '+all' which allows anyone to send mail as your domain.",
                "recommendation": "Replace '+all' with '~all' or '-all' to restrict unauthorized senders.",
                "record": spf
            }
        else:
            return {
                "status": "warning",
                "message": "SPF record found but may not be properly configured.",
                "recommendation": "Ensure the SPF record ends with '~all' or '-all'.",
                "record": spf
            }


# Function to check DMARC record
def check_dmarc(domain):
    st.write("Checking DMARC Records")

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        dmarc_records = [str(rdata) for rdata in answers]

        valid_records = []
        for record in dmarc_records:
            if "v=DMARC1" in record:
                valid_records.append(record)

        if not valid_records:
            return {
                "status": "warning",
                "message": "No valid DMARC record found.",
                "recommendation": "Add a DMARC record to protect against email spoofing."
            }

        # Check policy
        record = valid_records[0]
        if "p=none" in record:
            return {
                "status": "warning",
                "message": "DMARC policy is set to 'none', which only monitors but doesn't protect.",
                "recommendation": "Consider changing to 'p=quarantine' or 'p=reject' for better protection.",
                "record": record
            }
        elif "p=quarantine" in record:
            return {
                "status": "success",
                "message": "DMARC policy is set to 'quarantine', which flags suspicious emails.",
                "record": record
            }
        elif "p=reject" in record:
            return {
                "status": "success",
                "message": "DMARC policy is set to 'reject', which provides the strongest protection.",
                "record": record
            }
        else:
            return {
                "status": "warning",
                "message": "DMARC record found but policy is unclear.",
                "record": record
            }
    except Exception as e:
        return {
            "status": "warning",
            "message": f"No DMARC record found: {str(e)}",
            "recommendation": "Add a DMARC record to protect against email spoofing."
        }


# Function to check DNSSEC
def check_dnssec(domain):
    st.write("Checking DNSSEC Records")

    try:
        # First try to check for DS records
        try:
            ds_answers = dns.resolver.resolve(domain, 'DS')
            st.write("Checking DS")
            return {
                "status": "success",
                "message": "DNSSEC is configured with DS records present.",
                "records": [str(rdata) for rdata in ds_answers]
            }
        except dns.resolver.NoAnswer:
            # No DS records, but let's check for DNSKEY records
            pass
        except Exception:
            # Other error with DS, try DNSKEY
            pass

        # Try to check for DNSKEY records
        try:
            dnskey_answers = dns.resolver.resolve(domain, 'DNSKEY')
            return {
                "status": "success",
                "message": "DNSSEC is configured with DNSKEY records present.",
                "records": [str(rdata) for rdata in dnskey_answers]
            }
        except dns.resolver.NoAnswer:
            # No DNSKEY records either
            pass
        except Exception:
            # Other error with DNSKEY
            pass

        # Try one more approach - check if DO flag works
        resolver = dns.resolver.Resolver()
        resolver.use_edns(0, dns.flags.DO, 4096)

        try:
            # Try to get a signed response
            answer = resolver.resolve(domain, 'A')
            if answer.response.flags & dns.flags.AD:
                return {
                    "status": "success",
                    "message": "DNSSEC validation successful (AD flag set).",
                }
            else:
                # Last attempt - check parent domain for DS records
                parent_domain = '.'.join(domain.split('.')[1:]) if '.' in domain else None
                if parent_domain and len(parent_domain.split('.')) > 1:
                    try:
                        parent_ds = dns.resolver.resolve(domain, 'DS', raise_on_no_answer=False)
                        if parent_ds:
                            return {
                                "status": "success",
                                "message": f"DNSSEC is configured via parent domain.",
                                "records": [str(rdata) for rdata in parent_ds]
                            }
                    except Exception:
                        pass
        except Exception:
            pass

        # If we get here, DNSSEC is likely not configured
        return {
            "status": "warning",
            "message": "DNSSEC does not appear to be configured.",
            "recommendation": "Consider implementing DNSSEC to protect against DNS spoofing attacks."
        }
    except Exception as e:
        return {
            "status": "info",
            "message": f"Could not determine DNSSEC status: {str(e)}",
            "recommendation": "Manually verify DNSSEC configuration."
        }


# Function to test for zone transfers
def check_zone_transfer(domain):
    st.write("Checking Zone Transfer Records")
    try:
        nameservers = []
        answers = dns.resolver.resolve(domain, 'NS')
        for rdata in answers:
            nameservers.append(str(rdata))

        vulnerable_ns = []
        for ns in nameservers:
            try:
                # Remove trailing dot if present
                ns = ns.rstrip('.')
                # Try to get IP of nameserver
                ns_ip = socket.gethostbyname(ns)

                # Attempt zone transfer (with a short timeout)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
                vulnerable_ns.append(ns)
            except Exception:
                # This is actually good - zone transfer should fail
                pass

        if vulnerable_ns:
            return {
                "status": "error",
                "message": f"Zone transfer possible from nameservers: {', '.join(vulnerable_ns)}",
                "recommendation": "Disable zone transfers to prevent information disclosure."
            }
        else:
            return {
                "status": "success",
                "message": "Zone transfers are properly restricted."
            }
    except Exception as e:
        return {
            "status": "info",
            "message": f"Could not test zone transfers: {str(e)}"
        }


# Function to calculate security score
def calculate_score(results):
    st.write("Check completed")
    score = 100
    deductions = {
        "spf_missing": 15,
        "spf_multiple": 10,
        "spf_plusall": 20,
        "dmarc_missing": 15,
        "dmarc_none": 10,
        "dnssec_missing": 10,
        "zone_transfer": 25
    }

    reasons = []

    # SPF checks
    if results["spf"]["status"] == "warning":
        score -= deductions["spf_missing"]
        reasons.append("Missing SPF record (-15)")
    elif results["spf"]["status"] == "error":
        if "Multiple SPF records" in results["spf"]["message"]:
            score -= deductions["spf_multiple"]
            reasons.append("Multiple SPF records (-10)")
        elif "+all" in results["spf"].get("record", ""):
            score -= deductions["spf_plusall"]
            reasons.append("SPF allows any sender (+all) (-20)")

    # DMARC checks
    if results["dmarc"]["status"] == "warning":
        if "No valid DMARC record" in results["dmarc"]["message"]:
            score -= deductions["dmarc_missing"]
            reasons.append("Missing DMARC record (-15)")
        elif "p=none" in results["dmarc"].get("record", ""):
            score -= deductions["dmarc_none"]
            reasons.append("DMARC policy set to 'none' (-10)")

    # DNSSEC checks
    if results["dnssec"]["status"] == "warning":
        score -= deductions["dnssec_missing"]
        reasons.append("DNSSEC not implemented (-10)")

    # Zone transfer checks
    if results["zone_transfer"]["status"] == "error":
        score -= deductions["zone_transfer"]
        reasons.append("Zone transfers allowed (-25)")

    # Ensure score doesn't go below 0
    score = max(0, score)

    return {
        "score": score,
        "reasons": reasons
    }


# Main analysis function
def analyze_domain(domain):
    # First check if domain exists
    if not domain_exists(domain):
        return {
            "domain_exists": False,
            "message": "This domain does not exist in DNS records.",
            "score": {
                "score": 0,
                "reasons": ["Domain does not exist (-100)"]
            },
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    with st.spinner(f"Analyzing {domain}..."):
        # Get basic DNS records
        dns_records = check_basic_dns(domain)

        # Check SPF
        spf_result = check_spf(dns_records.get('TXT', []))

        # Check DMARC
        dmarc_result = check_dmarc(domain)

        # Check DNSSEC
        dnssec_result = check_dnssec(domain)

        # Check Zone Transfer
        zone_transfer_result = check_zone_transfer(domain)

        # Compile results
        results = {
            "basic_dns": dns_records,
            "spf": spf_result,
            "dmarc": dmarc_result,
            "dnssec": dnssec_result,
            "zone_transfer": zone_transfer_result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Calculate security score
        score_result = calculate_score(results)
        results["score"] = score_result

        results["domain_exists"] = True
        return results


# Display results function
def display_results(results):
    # Check if domain exists
    if not results.get("domain_exists", True):
        st.error(results["message"])
        st.error("Security Score: 0/100")
        st.write("Score deductions:")
        st.write("- Domain does not exist (-100)")
        st.caption(f"Analysis completed at: {results['timestamp']}")
        return

    # Display security score
    score = results["score"]["score"]
    if score >= 90:
        st.success(f"Security Score: {score}/100")
    elif score >= 70:
        st.warning(f"Security Score: {score}/100")
    else:
        st.error(f"Security Score: {score}/100")

    if results["score"]["reasons"]:
        st.write("Score deductions:")
        for reason in results["score"]["reasons"]:
            st.write(f"- {reason}")

    # Create tabs for different sections
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Basic DNS Records",
        "Email Security (SPF/DMARC)",
        "DNSSEC",
        "Zone Transfer",
        "Recommendations"
    ])

    # Tab 1: Basic DNS Records
    with tab1:
        st.subheader("DNS Records")
        for record_type, records in results["basic_dns"].items():
            if records and records[0] != f"Error: The DNS response does not contain an answer to the question: {domain_name}. IN {record_type}":
                st.write(f"**{record_type} Records:**")
                for record in records:
                    st.code(record)

    # Tab 2: Email Security
    with tab2:
        st.subheader("SPF (Sender Policy Framework)")
        if results["spf"]["status"] == "success":
            st.success(results["spf"]["message"])
        elif results["spf"]["status"] == "warning":
            st.warning(results["spf"]["message"])
        else:
            st.error(results["spf"]["message"])

        if "recommendation" in results["spf"]:
            st.info(f"Recommendation: {results['spf']['recommendation']}")

        if "record" in results["spf"]:
            st.code(results["spf"]["record"])

        st.subheader("DMARC (Domain-based Message Authentication)")
        if results["dmarc"]["status"] == "success":
            st.success(results["dmarc"]["message"])
        elif results["dmarc"]["status"] == "warning":
            st.warning(results["dmarc"]["message"])
        else:
            st.error(results["dmarc"]["message"])

        if "recommendation" in results["dmarc"]:
            st.info(f"Recommendation: {results['dmarc']['recommendation']}")

        if "record" in results["dmarc"]:
            st.code(results["dmarc"]["record"])

    # Tab 3: DNSSEC
    with tab3:
        st.subheader("DNSSEC (DNS Security Extensions)")
        if results["dnssec"]["status"] == "success":
            st.success(results["dnssec"]["message"])
            if "records" in results["dnssec"]:
                for record in results["dnssec"]["records"]:
                    st.code(record)
        else:
            st.warning(results["dnssec"]["message"])
            if "recommendation" in results["dnssec"]:
                st.info(f"Recommendation: {results['dnssec']['recommendation']}")

    # Tab 4: Zone Transfer
    with tab4:
        st.subheader("Zone Transfer Vulnerability")
        if results["zone_transfer"]["status"] == "success":
            st.success(results["zone_transfer"]["message"])
        elif results["zone_transfer"]["status"] == "error":
            st.error(results["zone_transfer"]["message"])
            st.info(f"Recommendation: {results['zone_transfer']['recommendation']}")
        else:
            st.info(results["zone_transfer"]["message"])

    # Tab 5: Recommendations
    with tab5:
        st.subheader("Security Recommendations")
        recommendations = []

        if "recommendation" in results["spf"]:
            recommendations.append(f"**SPF:** {results['spf']['recommendation']}")

        if "recommendation" in results["dmarc"]:
            recommendations.append(f"**DMARC:** {results['dmarc']['recommendation']}")

        if "recommendation" in results["dnssec"]:
            recommendations.append(f"**DNSSEC:** {results['dnssec']['recommendation']}")

        if "recommendation" in results["zone_transfer"]:
            recommendations.append(f"**Zone Transfer:** {results['zone_transfer']['recommendation']}")

        if recommendations:
            for rec in recommendations:
                st.markdown(rec)
        else:
            st.success("No critical recommendations. Your DNS configuration appears to be secure!")

    # Display timestamp
    st.caption(f"Analysis completed at: {results['timestamp']}")


# Main app logic
if st.button("Analyze"):
    if domain_name:
        sanitized_domain = sanitize_domain(domain_name)
        if sanitized_domain:
            st.info(f"Analyzing domain: {sanitized_domain}")
            results = analyze_domain(sanitized_domain)
            display_results(results)
        else:
            st.error("Invalid domain name format. Please enter a valid domain like 'example.com'")
    else:
        st.warning("Please enter a domain name first.")

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

