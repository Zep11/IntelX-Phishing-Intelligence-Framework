
def check_url_length(url):                                  #Checking length of the URL 
    length=len(url)

    return{
        "length" : length ,
        "its_long" : length > 75
    }

def checking_at_symbol(url):                                #Checking @-symbol present in the URL 
    return '@' in url 

def sus_key(url):                                           #Checking presence of Suspicious words . 
    keywords = [ "login",
                 "verify",
                 "secure",
                 "account",
                 "update",
                 "password",
                 "signin",
                 "payment",
                 "banking",
                 "wallet",
                 "confirm"
                 ]
    matched_keywords= []
    for keyword in keywords:
        if keyword in url:
            matched_keywords.append(keyword)
    return matched_keywords

def http_check(scheme):                                     #Checking whether it contains http or https 
    if scheme == "http":
        return True
    else:
        return False 
    
def punnycode_check(domain):                                #Checking Punny code is Present or not in the URL 
    if domain is None:
        return False
    
    if domain.lower() in "xn--":
        return True 
    else:
        return False 
    
def url_shorteners(domain):
    if domain is None:
        return False
    
    domain=domain.lower()
    shorteners= [    
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at"
    ]
    for url_shortner in shorteners :
        if domain == url_shortner:
            return True
    
    return False

def subd_check(subdomain):
    subd1=subdomain.split(".")
    subd_count= len(subd1)
    return subd_count