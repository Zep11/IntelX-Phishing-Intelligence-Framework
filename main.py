from validator import valid_url
from parser import parse_url
from rich.console import Console 
console=Console()
from signals import check_url_length
from signals import checking_at_symbol
from signals import sus_key
from signals import http_check
from signals import punnycode_check
from signals import url_shorteners
from signals import subd_check


# TOOL INTRO 
def welcome():
    print("=" * 50)
    console.print("        PHISHING URL ANALYZER" , style="bold red")
    print(" Just Enter the URL and Let me do my work for you  ")
    print("=" * 50)

# FETCHING THE URL 
def get_url():
    url = input("\nEnter a URL: ").strip().lower()
    return url


welcome()

user_url=get_url()

if valid_url(user_url):
    console.print("\n[Analysing] ..." , style="blue")
    parsed_data=parse_url(user_url)

    console.print("\n[Parsed URL Information]" , style="blue ")
    console.print("-" * 30 , style="dim")
    print("Scheme :", parsed_data["scheme"])
    print("Domain :", parsed_data["domain"])
    print("hostname :", parsed_data["hostname"])
    print("Subdomain :", parsed_data["subdomain"])
    print("Path   :", parsed_data["path"])
    print("Query  :", parsed_data["query"])
    console.print("-" * 30, style="dim")

else:
    print("Invalid URL ")

# Checking URL Features
# Checking URL length

length_info= check_url_length(user_url)

#Printing the URL Features 
console.print("[SIGNALS] " , style ="blue")
console.print("------------------------------", style="dim" )
if length_info["its_long"]:
    console.print("⚠️  Suspicious: Long URL detected" , style="yellow")
else:
    console.print("✅ URL length looks normal", style="green")

# Checking some signals for URL CHECKS 

if checking_at_symbol(user_url):
    console.print("⚠️  '@' symbol detected." , style="yellow")
else:
    console.print("✅ No '@' symbol found." , style="green")
 
if parsed_data["is_ip"]:
    console.print("⚠️  Hostname detected an IP address." , style="yellow")
else:
    console.print("✅ Hostname detected a domain name." , style="green")

keywords_matched = sus_key(user_url)
if keywords_matched:
    console.print(f"⚠️   Suspicious keywords found : {keywords_matched} ", style="yellow")
else:
    console.print("✅ No Suspicious Keywords found " , style="green")

http_signals=http_check(parsed_data["scheme"])
console.print(f"⚠️   http detected in the URL : {http_signals} " , style="yellow")

punny_check = punnycode_check(parsed_data["domain"])
if punny_check == True :
    console.print ("⚠️  Suspicious :  Punnycode Detected ", style="yellow")

shortner_check = url_shorteners(parsed_data["domain"])
if shortner_check == True:
    console.print ("⚠️  Suspicious : Link shortner Detected " , style="yellow")
    
subd_count_check = subd_check(parsed_data["subdomain"])
if subd_count_check > 3:
    console.print(f"⚠️   Suspicious - Count of Subdomain : {subd_count_check}" , style="yellow")
else:
    console.print (f"✅  - Subdomain count is Normal " , style="green")
