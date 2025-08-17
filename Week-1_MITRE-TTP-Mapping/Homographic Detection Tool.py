import difflib
import re

# List of known legitimate domains to compare against
trusted_domains = [
    "google.com",
    "facebook.com",
    "github.com",
    "amazon.com",
    "microsoft.com"
]

# Function to calculate similarity between two domains
def is_similar(domain1, domain2, threshold=0.85):
    ratio = difflib.SequenceMatcher(None, domain1, domain2).ratio()
    return ratio >= threshold

# Function to extract domain from a URL
def extract_domain(url):
    match = re.search(r"https?://(www\.)?([^/]+)", url)
    return match.group(2) if match else ""

# Function to check if URL is homographic
def detect_homograph(url):
    domain = extract_domain(url)
    print(f"Checking: {domain}")
    for trusted in trusted_domains:
        if is_similar(domain, trusted) and domain != trusted:
            print(f"[ALERT] Possible homographic attack detected: {domain} vs {trusted}")
            return True
    print("[SAFE] No homograph detected.")
    return False

# Test URLs
urls_to_check = [
    "http://www.goоgle.com",  # Cyrillic 'о'
    "http://www.github.com",
    "https://www.faceb00k.com",  # zeros instead of 'o'
    "https://www.amaz0n.com",   # zero instead of 'o'
    "https://www.micr0soft.com"
]

for url in urls_to_check:
    detect_homograph(url)
