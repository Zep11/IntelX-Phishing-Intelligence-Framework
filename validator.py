from urllib.parse import urlparse
# Checking Whether the URL is Valid or not 
def valid_url(url):
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.netloc:
        return False

    return True
    