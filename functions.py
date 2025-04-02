import re
import ssl
import time
import socket
import dns.zone
import dns.query
import dns.resolver
import streamlit as st
from datetime import datetime


@st.cache_resource  # Cache the created resolver object
def get_dns_resolver():
    """Creates and returns a configured DNS resolver instance."""
    resolver = dns.resolver.Resolver()
    # Explicitly set reliable public nameservers
    resolver.nameservers = [
        '8.8.8.8',
        '8.8.4.4',
        '1.1.1.1',
        '1.0.0.1',
        '9.9.9.9',
        '208.67.222.222',
        '149.112.112.112',
        '208.67.220.220']  # Google, Cloudflare, Quad9, Cisco(OpenDNS)
    # Set reasonable timeouts
    resolver.timeout = 2.0
    resolver.lifetime = 5.0
    return resolver


def domain_exists(domain):
    try:
        resolver = get_dns_resolver()
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

    # st.write("Checking Basic DNS Records")

    # Create a Streamlit progress bar
    progress_bar = st.progress(0)
    status_text = st.empty()

    resolver = get_dns_resolver()

    for i, record_type in enumerate(record_types):
        # Update progress bar and status text
        progress = i / len(record_types)
        progress_bar.progress(progress)
        status_text.text(f"Checking {record_type} records...")

        try:
            answers = resolver.resolve(domain, record_type)
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

    # st.write("Checking SPF Records")

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
    # st.write("Checking DMARC Records")

    resolver = get_dns_resolver()

    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = resolver.resolve(dmarc_domain, 'TXT')
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
    # st.write("Checking DNSSEC Records")  # Keep for debugging if needed

    resolver = get_dns_resolver()

    try:
        # First try to check for DS records using the configured resolver
        try:
            # Use the configured resolver instance
            ds_answers = resolver.resolve(domain, 'DS')
            # st.write("Checking DS") # Debugging line
            return {
                "status": "success",
                "message": "DNSSEC is configured with DS records present.",
                "records": [str(rdata) for rdata in ds_answers]
            }
        except dns.resolver.NoAnswer:
            pass  # Continue if no DS records
        except Exception as e:
            st.write(f"DS check error: {e}")  # Log specific error
            pass  # Continue on other DS errors

        # Try to check for DNSKEY records using the configured resolver
        try:
            # Use the configured resolver instance
            dnskey_answers = resolver.resolve(domain, 'DNSKEY')
            return {
                "status": "success",
                "message": "DNSSEC is configured with DNSKEY records present.",
                "records": [str(rdata) for rdata in dnskey_answers]
            }
        except dns.resolver.NoAnswer:
            pass  # Continue if no DNSKEY records
        except Exception as e:
            st.write(f"DNSKEY check error: {e}")  # Log specific error
            pass  # Continue on other DNSKEY errors

        # Try the AD flag check using the configured resolver
        # Tell the resolver we want DNSSEC data (DO bit)
        resolver.use_edns(0, dns.flags.DO, 4096)
        try:
            # Use the configured resolver instance
            answer = resolver.resolve(domain, 'A')  # Check A record with DO flag set
            if answer.response.flags & dns.flags.AD:
                return {
                    "status": "success",
                    "message": "DNSSEC validation successful (AD flag set).",
                }
            # Removed the redundant parent DS check here as it was likely incorrect logic
        except Exception as e:
            st.write(f"AD flag check error: {e}")  # Log specific error
            pass  # Continue if AD flag check fails

        # If all checks above failed, DNSSEC is likely not configured or verifiable this way
        return {
            "status": "warning",
            "message": "DNSSEC does not appear to be configured or verifiable.",
            "recommendation": "Consider implementing DNSSEC or check configuration."
        }

    except Exception as e:
        # Catch potential errors during resolver configuration or general failures
        st.write(f"General DNSSEC check error: {e}")  # Log specific error
        return {
            "status": "info",
            "message": f"Could not determine DNSSEC status: {str(e)}",
            "recommendation": "Manually verify DNSSEC configuration."
        }


# Function to test for zone transfers
def check_zone_transfer(domain):
    # st.write("Checking Zone Transfer Records")

    resolver = get_dns_resolver()

    try:
        nameservers = []
        answers = resolver.resolve(domain, 'NS')
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


def check_caa(domain):
    """Checks for CAA DNS records."""

    resolver = get_dns_resolver()

    try:
        st.write(f"Attempting CAA lookup for {domain} using {resolver.nameservers}")  # Log resolver
        caa_answers = resolver.resolve(domain, 'CAA')
        records = [str(rdata) for rdata in caa_answers]
        st.write(f"Successfully retrieved CAA records: {records}")  # Log success

        if records:
            # Check for common restrictive policies
            issue_wild_present = any('issuewild' in r.lower() for r in records)
            issue_present = any('issue ' in r.lower() for r in records)  # Space after issue is important

            message = "CAA records found, specifying allowed CAs."
            if not issue_wild_present and not issue_present:
                message = "CAA records found, but may not explicitly restrict issuance (e.g., only iodef). Review records."

            return {
                "status": "success",
                "message": message,
                "records": records,
                "recommendation": "Ensure these records reflect your intended Certificate Authorities."
            }
        else:
            st.write("CAA lookup returned answers, but the records list was empty.")  # Log empty list case
            # This case should technically be caught by NoAnswer, but added for safety
            return {
                "status": "warning",
                "message": "No CAA records found. Any CA can issue certificates for this domain.",
                "recommendation": "Consider adding CAA records to restrict certificate issuance to specific CAs (e.g., Let's Encrypt, DigiCert)."
            }

    except dns.resolver.NoAnswer:
        st.write(f"CAA lookup for {domain} resulted in NoAnswer.")  # Log NoAnswer
        return {
            "status": "warning",
            "message": "No CAA records found. Any CA can issue certificates for this domain.",
            "recommendation": "Consider adding CAA records to restrict certificate issuance to specific CAs (e.g., Let's Encrypt, DigiCert)."
        }
    except dns.resolver.NXDOMAIN:
        st.write(f"CAA lookup failed: NXDOMAIN for {domain}.")  # Log NXDOMAIN
        return {
            "status": "error",
            "message": f"Domain '{domain}' does not exist.",
            "recommendation": "Check domain spelling."
        }
    except Exception as e:
        st.write(f"CAA lookup for {domain} failed with unexpected error: {type(e).__name__} - {e}")  # Log other errors
        return {
            "status": "error",  # Changed from info to error as lookup failed
            "message": f"Could not retrieve CAA records: {str(e)}",
            "recommendation": "DNS lookup failed. Check domain or try again later."
        }


def check_ssl_tls(domain):
    """Checks the SSL/TLS certificate for the domain on port 443."""
    # st.write(f"Checking SSL/TLS for {domain}") # Optional debug
    hostname = domain  # For SNI and hostname verification
    port = 443
    context = ssl.create_default_context()
    result = {
        "status": "error",  # Default to error
        "message": "Could not retrieve or validate certificate.",
        "details": {}
    }

    try:
        # Resolve domain first to handle potential NXDOMAIN early
        # Use a basic resolver here, don't need the configured one necessarily
        try:
            socket.getaddrinfo(hostname, port)
        except socket.gaierror:
            result["message"] = f"Domain '{hostname}' could not be resolved."
            return result

        # Connect and get certificate
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    result["message"] = "Server did not present a certificate."
                    return result

                # --- Extract Certificate Details ---
                expiry_date_str = cert.get('notAfter')
                issuer_tuples = cert.get('issuer', ())
                subject_tuples = cert.get('subject', ())
                subject_alt_names = cert.get('subjectAltName', ())

                # Parse expiry date
                expiry_date = None
                days_left = None
                if expiry_date_str:
                    try:
                        # Common format: 'Mar 30 12:00:00 2025 GMT'
                        expiry_date = datetime.strptime(expiry_date_str, '%b %d %H:%M:%S %Y %Z')
                        time_diff = expiry_date - datetime.utcnow()  # Compare with UTC
                        days_left = time_diff.days
                    except ValueError:
                        result["details"]["expiry_warning"] = "Could not parse expiry date format."

                # Format Issuer/Subject
                issuer = dict(x[0] for x in issuer_tuples)
                subject = dict(x[0] for x in subject_tuples)

                # Check Hostname Match (Common Name and SANs)
                cn = subject.get('commonName')
                alt_names = [name[1] for name in subject_alt_names if name[0].lower() == 'dns']
                valid_hostnames = set([cn] + alt_names) if cn else set(alt_names)

                hostname_match = False
                if hostname in valid_hostnames:
                    hostname_match = True
                # Check wildcard match (simple check)
                elif any(hn.startswith('*.') and hostname.endswith(hn[1:]) for hn in valid_hostnames):
                    hostname_match = True

                # --- Populate Result ---
                result["status"] = "success"  # Assume success unless checks fail
                result["message"] = "Certificate details retrieved."
                result["details"] = {
                    "subject_cn": cn,
                    "issuer_org": issuer.get('organizationName', 'N/A'),
                    "expiry_date": expiry_date.strftime('%Y-%m-%d') if expiry_date else "N/A",
                    "days_left": days_left,
                    "valid_hostnames": list(valid_hostnames),
                    "hostname_match": hostname_match
                }

                # Add specific warnings/errors based on checks
                if days_left is None:
                    result["status"] = "warning"
                    result["message"] = "Retrieved certificate, but expiry date unclear."
                elif days_left < 0:
                    result["status"] = "error"
                    result["message"] = f"Certificate EXPIRED {-days_left} days ago!"
                elif days_left < 30:
                    result["status"] = "warning"
                    result["message"] = f"Certificate expires soon (in {days_left} days)."
                # Only override success message if there's an expiry issue
                else:
                    result["message"] = "Certificate is valid."

                if not hostname_match:
                    result["status"] = "error"  # Hostname mismatch is a critical error
                    result["message"] += " CRITICAL: Certificate hostname mismatch!"

    except socket.timeout:
        result["message"] = f"Connection timed out connecting to {hostname}:{port}."
    except ConnectionRefusedError:
        result["message"] = f"Connection refused by {hostname}:{port}. (HTTPS not running?)"
    except ssl.SSLCertVerificationError as e:
        result["message"] = f"Certificate verification failed: {e}. (Possibly self-signed or untrusted CA)"
        result["details"]["verification_error"] = str(e)  # Add specific error detail
    except ssl.SSLError as e:
        result["message"] = f"An SSL error occurred: {e}."
    except OSError as e:  # Catch other potential socket/network errors
        result["message"] = f"Network error: {e}"
    except Exception as e:
        # Catch any other unexpected errors during processing
        # st.write(f"Unexpected SSL check error: {type(e).__name__} - {e}") # Debug
        result["message"] = f"An unexpected error occurred during SSL check: {str(e)}"

    return result


# Function to calculate security score
def calculate_score(results):
    # st.write("Check completed")
    score = 100
    deductions = {
        "spf_missing": 15,
        "spf_multiple": 10,
        "spf_plusall": 20,
        "dmarc_missing": 15,
        "dmarc_none": 10,
        "dnssec_missing": 10,
        "zone_transfer": 15,
        "caa_missing": 5
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

    if results["caa"]["status"] == "warning":
        # Check if the warning is specifically about missing records
        if "No CAA records found" in results["caa"]["message"]:
            score -= deductions["caa_missing"]
            reasons.append("Missing CAA record (-5)")

    # Ensure score doesn't go below 0
    score = max(0, score)

    return {
        "score": score,
        "reasons": reasons
    }


# Main analysis function
def analyze_domain_fresh(domain):
    """Performs a fresh DNS analysis without using cache."""

    # --- Use st.status to show progress ---
    with st.status(f"Analyzing {domain}...", expanded=True) as status:
        # First check if domain exists (do this *before* showing detailed status if possible)
        if not domain_exists(domain):
            status.update(label="Domain Not Found!", state="error", expanded=True)
            # Return the specific structure for non-existent domain
            return {
                "domain_exists": False,
                "message": "This domain does not exist in DNS records.",
                "score": {"score": 0, "reasons": ["Domain does not exist (-100)"]},
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # --- Start detailed checks ---
        status.update(label="Checking Basic DNS Records...")
        dns_records = check_basic_dns(domain)  # This function has its own progress bar now inside the status
        st.write("✅ Basic DNS Records Checked.")

        status.update(label="Checking SPF Record...")
        spf_result = check_spf(dns_records.get('TXT', []))
        st.write("✅ SPF Record Checked.")

        status.update(label="Checking DMARC Record...")
        dmarc_result = check_dmarc(domain)
        st.write("✅ DMARC Record Checked.")

        status.update(label="Checking DNSSEC Configuration...")
        dnssec_result = check_dnssec(domain)
        st.write("✅ DNSSEC Configuration Checked.")

        status.update(label="Checking Zone Transfer Vulnerability...")
        zone_transfer_result = check_zone_transfer(domain)
        st.write("✅ Zone Transfer Vulnerability Checked.")

        status.update(label="Checking CAA Records...")
        CAA_result = check_caa(domain)
        st.write("✅ CAA Record Checked.")

        status.update(label="Performing SSL/TLS Check...")
        ssl_result = check_ssl_tls(domain)
        st.write("✅ SSL/TLS Check Completed.")

        status.update(label="Calculating Score...")
        # Compile results (before score calculation)
        results = {
            "basic_dns": dns_records,
            "spf": spf_result,
            "dmarc": dmarc_result,
            "dnssec": dnssec_result,
            "zone_transfer": zone_transfer_result,
            "caa": CAA_result,
            "ssl_tls": ssl_result,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "domain_exists": True
        }
        score_result = calculate_score(results)
        results["score"] = score_result
        st.write("✅ Score Calculated.")

        # --- Mark status as complete ---
        status.update(label="Analysis Complete!", state="complete", expanded=False)

    # Return results *after* the 'with' block
    return results


# --- Cached wrapper function ---
@st.cache_data(ttl=3600)  # Cache results for 1 hour
def analyze_domain_cached(domain):
    """Cached wrapper that calls the fresh analysis function."""

    # Note: st.status will still run inside here if cache is missed.
    # If cache hits, the status block won't execute, which is desired.
    return analyze_domain_fresh(domain)


def display_results(domain, results):  # Pass domain name here
    # Check if domain exists (handled before calling, but good practice)
    if not results.get("domain_exists", True):
        # This part is now handled before calling display_results,
        # but keep it as a fallback just in case.
        st.error(results["message"])
        st.error("Security Score: 0/100")
        st.write("Score deductions:")
        st.write("- Domain does not exist (-100)")
        st.caption(f"Analysis completed at: {results['timestamp']}")
        return

    # --- Score display is now moved outside this function ---

    # Create tabs for different sections with icons
    tab_titles = [
        "📄 Basic DNS",
        "📧 Email Security",
        "🔒 DNSSEC",
        "🛡️ CAA Records",
        "📜 SSL/TLS Cert",
        "🕵️ Zone Transfer",
        "💡 Recommendations"
    ]
    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(tab_titles)

    # Tab 1: Basic DNS Records
    with tab1:
        st.subheader("DNS Records")
        st.caption("Core DNS records defining your domain's basic infrastructure.")
        for record_type, records in results["basic_dns"].items():
            st.markdown(f"**{record_type} Records:**")  # Use markdown for bold
            if not records:
                st.caption("No records of this type found.")
            elif "Error: The DNS query name does not exist" in records[0]:
                st.caption("Domain does not exist or no records of this type found.")
            elif "Error: The DNS response does not contain an answer" in records[0]:
                st.caption("No records of this type found.")
            elif "Error:" in records[0]:
                st.warning(f"⚠️ Could not retrieve records: {records[0]}")
            else:
                for record in records:
                    st.code(record, language=None)  # Use language=None for plain text

    # Tab 2: Email Security
    with tab2:
        st.subheader("SPF (Sender Policy Framework)")
        st.caption("""
        **What is SPF?** Helps prevent email spoofing by defining authorized mail servers.
        **Why it matters:** Protects your domain's reputation and reduces phishing risks.
        """)
        spf_res = results["spf"]
        if spf_res["status"] == "success":
            st.success(f"✅ {spf_res['message']}")
        elif spf_res["status"] == "warning":
            st.warning(f"⚠️ {spf_res['message']}")
        else:
            st.error(f"❌ {spf_res['message']}")

        if "recommendation" in spf_res:
            st.info(f"💡 Recommendation: {spf_res['recommendation']}")
        if "record" in spf_res:
            st.code(spf_res["record"], language=None)

        st.divider()  # Add divider between SPF/DMARC

        st.subheader("DMARC (Domain-based Message Authentication)")
        st.caption("""
        **What is DMARC?** Tells receiving email servers how to handle messages failing SPF/DKIM checks.
        **Why it matters:** Provides reporting and policy enforcement for email authentication.
        """)
        dmarc_res = results["dmarc"]
        if dmarc_res["status"] == "success":
            st.success(f"✅ {dmarc_res['message']}")
        elif dmarc_res["status"] == "warning":
            st.warning(f"⚠️ {dmarc_res['message']}")
        else:
            st.error(f"❌ {dmarc_res['message']}")

        if "recommendation" in dmarc_res:
            st.info(f"💡 Recommendation: {dmarc_res['recommendation']}")
        if "record" in dmarc_res:
            st.code(dmarc_res["record"], language=None)

    # Tab 3: DNSSEC
    with tab3:
        st.subheader("DNSSEC (DNS Security Extensions)")
        st.caption("""
        **What is DNSSEC?** Adds a layer of authentication to DNS lookups, preventing DNS spoofing/cache poisoning.
        **Why it matters:** Ensures users connect to the legitimate server for your domain.
        """)
        dnssec_res = results["dnssec"]
        if dnssec_res["status"] == "success":
            st.success(f"✅ {dnssec_res['message']}")
            if "records" in dnssec_res and dnssec_res["records"]:
                st.write("**Records Found:**")
                for record in dnssec_res["records"]:
                    st.code(record, language=None)
        elif dnssec_res["status"] == "warning":
            st.warning(f"⚠️ {dnssec_res['message']}")
            if "recommendation" in dnssec_res:
                st.info(f"💡 Recommendation: {dnssec_res['recommendation']}")
        else:  # Info or other errors
            st.info(f"ℹ️ {dnssec_res['message']}")
            if "recommendation" in dnssec_res:
                st.info(f"💡 Recommendation: {dnssec_res['recommendation']}")

    # Tab 4: CAA records
    with tab4:
        st.subheader("CAA (Certification Authority Authorization)")
        st.caption("""
        **What is CAA?** Specifies which Certificate Authorities (CAs) are allowed to issue SSL/TLS certificates for your domain.
        **Why it matters:** Helps prevent unauthorized or mis-issued certificates, enhancing web security.
        """)
        caa_res = results["caa"]
        if caa_res["status"] == "success":
            st.success(f"✅ {caa_res['message']}")
            if "records" in caa_res and caa_res["records"]:
                st.write("**Records Found:**")
                for record in caa_res["records"]:
                    # Format CAA records for better readability
                    # Example record: '0 issue "letsencrypt.org"'
                    parts = record.split(' ', 2)
                    if len(parts) == 3:
                        flag, tag, value = parts
                        stripped_value = value.strip('"')  # Remove quotes BEFORE the f-string
                        st.code(f"Flag: {flag}, Tag: {tag}, Value: {stripped_value}", language=None)

                    else:
                        st.code(record, language=None)  # Fallback for unexpected format
            if "recommendation" in caa_res:
                st.info(f"💡 Recommendation: {caa_res['recommendation']}")
        elif caa_res["status"] == "warning":
            st.warning(f"⚠️ {caa_res['message']}")
            if "recommendation" in caa_res:
                st.info(f"💡 Recommendation: {caa_res['recommendation']}")
        else:  # Error
            st.error(f"❌ {caa_res['message']}")
            if "recommendation" in caa_res:
                st.info(f"💡 Recommendation: {caa_res['recommendation']}")

    # Tab 5: SSL/TLS check
    with tab5:
        st.subheader("SSL/TLS Certificate Analysis (Port 443)")
        st.caption("""
           **What is SSL/TLS?** Encrypts communication between a browser and the web server. Essential for HTTPS.
           **Why it matters:** Protects data privacy and integrity, builds user trust. Checks certificate validity, expiry, and hostname match.
           """)
        ssl_res = results["ssl_tls"]
        details = ssl_res.get("details", {})

        if ssl_res["status"] == "success":
            st.success(f"✅ {ssl_res['message']}")
        elif ssl_res["status"] == "warning":
            st.warning(f"⚠️ {ssl_res['message']}")
        else:  # Error
            st.error(f"❌ {ssl_res['message']}")

        # Display details if available
        if details:
            st.markdown(f"**Subject Common Name (CN):** `{details.get('subject_cn', 'N/A')}`")
            st.markdown(f"**Issuer Organization:** `{details.get('issuer_org', 'N/A')}`")
            st.markdown(f"**Expiry Date:** `{details.get('expiry_date', 'N/A')}`")

            days_left = details.get('days_left')
            if days_left is not None:
                if days_left < 0:
                    st.error(f"**Days Remaining:** Expired!")
                elif days_left < 30:
                    st.warning(f"**Days Remaining:** {days_left} (Expires Soon!)")
                else:
                    st.success(f"**Days Remaining:** {days_left}")

            match = details.get('hostname_match')
            if match is True:
                st.success(f"**Hostname Match:** ✅ Yes (Certificate covers '{domain}')")
            elif match is False:
                st.error(f"**Hostname Match:** ❌ No (Certificate does NOT cover '{domain}')")

            if details.get('valid_hostnames'):
                with st.expander("Valid Hostnames Listed in Certificate (CN + SANs)"):
                    st.write(details['valid_hostnames'])

            if details.get('verification_error'):
                st.warning(f"**Verification Note:** {details['verification_error']}")

    # Tab 6: Zone Transfer
    with tab6:
        st.subheader("Zone Transfer Vulnerability")
        st.caption("""
        **What is Zone Transfer (AXFR)?** A mechanism to replicate DNS records between servers. Should usually be restricted.\n
        **Why it matters:** If allowed publicly, attackers can easily download *all* your DNS records, revealing infrastructure details.
        """)
        zt_res = results["zone_transfer"]
        if zt_res["status"] == "success":
            st.success(f"✅ {zt_res['message']}")
        elif zt_res["status"] == "error":
            st.error(f"❌ {zt_res['message']}")
            st.info(f"💡 Recommendation: {zt_res['recommendation']}")
        else:  # Info
            st.info(f"ℹ️ {zt_res['message']}")

    # Tab 7: Recommendations
    with tab7:
        st.subheader("Summary of Recommendations")
        recommendations = []
        # ... (keep existing logic to populate recommendations) ...
        ssl_status = results["ssl_tls"]["status"]
        ssl_details = results["ssl_tls"].get("details", {})

        if recommendations:
            st.warning("⚠️ Please review the following recommendations based on the analysis:")
            for i, rec in enumerate(recommendations):
                st.markdown(f"{i + 1}. {rec}")  # Use numbered list

            if ssl_status == 'error' or (ssl_status == 'warning' and ssl_details.get('days_left', 999) < 30):
                recommendations.append(f"**SSL/TLS:** Review certificate status: {results['ssl_tls']['message']}")

            if "recommendation" in results["caa"] and results["caa"]["status"] != "success":
                recommendations.append(f"**CAA:** {results['caa']['recommendation']}")
        else:
            st.success("✅ No critical recommendations found based on these checks!")

    # Display timestamp (keep as is)
    st.caption(f"Analysis completed at: {results['timestamp']}")
