
import re
from urllib.parse import urlparse

import streamlit as st

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("Cloud-Based Phishing URL Detector")
st.write("Check a URL for common phishing warning signs.")

st.warning(
    "Educational prototype only. A result cannot guarantee "
    "that a website is safe."
)


def check_url(raw_url):
    url = raw_url.strip()

    if not url:
        return None, ["Please enter a URL."]

    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url

    try:
        parsed = urlparse(url)
        host = parsed.hostname
    except ValueError:
        host = None
        parsed = None

    if (
        not host
        or "." not in host
        or " " in host
    ):
        return None, ["Enter a valid-looking domain, such as example.com."]

    flags = []
    hostname = host.lower()

    if parsed.scheme.lower() != "https":
        flags.append("The URL does not use HTTPS.")

    if "@" in url:
        flags.append("The URL contains an @ symbol.")

    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        flags.append("The hostname uses an IP address.")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        flags.append("The hostname contains a punycode label.")

    if hostname.count(".") >= 3:
        flags.append("The hostname has several subdomain levels.")

    suspicious_words = [
        "login", "verify", "account", "password",
        "secure", "update", "wallet", "confirm"
    ]

    if any(word in url.lower() for word in suspicious_words):
        flags.append("The URL contains account-related words.")

    if len(url) > 100:
        flags.append("The URL is unusually long.")

    if "-" in hostname:
        flags.append("The hostname contains hyphens.")

    if flags:
        return "Suspicious indicators found", flags

    return "No obvious indicators found", [
        "The basic checks found no listed warning signs."
    ]


url_input = st.text_input(
    "Website URL",
    placeholder="https://example.com"
)

if st.button("Check URL", type="primary"):
    result, details = check_url(url_input)

    if result is None:
        st.error(details[0])

    elif result == "Suspicious indicators found":
        st.error("Warning: " + result)
        st.write("Warning signs:")
        for detail in details:
            st.write("- " + detail)

    else:
        st.success(result)
        st.write(details[0])

st.caption(
    "This prototype checks URL text only. It does not visit the "
    "website. A clean result does not prove a site is safe."
)
