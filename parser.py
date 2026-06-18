from urllib.parse import urlparse
import tldextract   

def parse_url(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    return{
        "scheme" : parsed.scheme , 
        "domain" :  f"{extracted.domain}.{extracted.suffix}" ,
        "subdomain" : extracted.subdomain ,
        "path" : parsed.path , 
        "query" : parsed.query
    }

