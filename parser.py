from urllib.parse import urlparse
import tldextract   
import re

#Rule for IP check
def ip_check(hostname):
    ip_pattern= r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(ip_pattern , hostname))


def parse_url(url):
    parsed = urlparse(url)
    hostname = parsed.netloc                                       
    if ip_check(hostname):                                #IP Check is conducted here

        return{
            "is_ip" : True ,
            "scheme" : parsed.scheme , 
            "domain" : None , 
            "hostname" : hostname,
            "subdomain" : None ,
            "path" : parsed.path , 
            "query" : parsed.query
        }
    else:    
        extracted = tldextract.extract(url)

        return{
            "is_ip" : False ,
            "scheme" : parsed.scheme , 
            "domain" :  f"{extracted.domain}.{extracted.suffix}" ,
            "subdomain" : extracted.subdomain ,
            "hostname" : None , 
            "path" : parsed.path , 
            "query" : parsed.query
    }

