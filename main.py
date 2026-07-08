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
from signals import port_check
from config  import (check_config, setup_config , load_config , api_check)
from Threat_Intel.virus_total import virustotal_lookup
from Threat_Intel.urlscan_io import urlscan_lookup 
from Threat_Intel.abuseipdb import abuseipdb_lookup
from Threat_Intel.whois import whois_lookup
from utils import create_report_folders
create_report_folders()                                      #Instantly Create Folders for reports

# TOOL INTRO 
def welcome():
    print("=" * 50)
    console.print("        PHISHING URL ANALYZER" , style="bold red")
    print(" Just Enter the URL and Let me do my work for you  ")
    print("=" * 50)
welcome()

#Checking for Configuration and LOADING 
if not check_config():
    setup_config()
    api_keys= load_config()
    print(api_keys)
else :
    api_keys = load_config()
    print(api_keys)
    if not api_check(api_keys):
        choice = input("\n No API Configured.\n "
                   "Would you like to add soxme for better results ? (Y/N)\n > ").strip().upper()
        if choice=="Y":
            setup_config()
            api_keys=load_config()     


# FETCHING THE URL 
def get_url():
    url = input("\nEnter a URL\n > ").strip().lower()
    return url




user_url=get_url()

if valid_url(user_url):
    console.print("\n[Analysing] ..." , style="blue")
    console.print("\n [Target URL]", style="blue" )
    console.print("------------------------------", style="dim" )
    print(user_url)
    parsed_data=parse_url(user_url)

    console.print("\n[Parsed URL Information]" , style="blue ")
    console.print("-" * 30 , style="dim")
    print("Scheme :", parsed_data["scheme"])
    print("Domain :", parsed_data["domain"])
    print("hostname :", parsed_data["hostname"])
    print("Subdomain :", parsed_data["subdomain"])
    print("Port :" , parsed_data["port"])
    print("Path   :", parsed_data["path"])
    print("Query  :", parsed_data["query"])
    console.print("-" * 30, style="dim")

else:
    print("Invalid URL ")

# Checking URL Features
# Checking URL length

length_info= check_url_length(user_url)

#Printing the URL Features 
console.print("[URL Inspection ] " , style ="blue")
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
if http_signals == True :
    console.print(f"⚠️  http detected in the URL : {http_signals} " , style="yellow")
else: 
    console.print(f"✅  http detected in the URL : {http_signals} " , style="green")
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
    console.print (f"✅  Subdomain count is Normal " , style="green")

check_port=port_check(parsed_data["port"])
console.print(f"⚠️  Non-Standard Port :  {check_port} " , style="yellow")
console.print("------------------------------", style="dim" )



vt_key = api_keys.get("vt_key")

print("\n[DEBUG] Calling VirusTotal...\n")  #TEMPORARY CALL STATEMENT   

vt_result = virustotal_lookup(user_url, vt_key)

# URLSCAN FIELD 
# calling the function to check 

urlscan_key = api_keys.get("urlscan_key")               
print("\n[DEBUG] Calling URLSCAN.IO ...\n")  #TEMPORARY CALL STATEMENT 
urlscan_result = urlscan_lookup(user_url, urlscan_key)

#ABUSEIPDB FIELD 
#calling the function to check 

pageip = urlscan_result.get("page_ip")
print("\n[DEBUG] Calling ABUSEIPDB ...\n")  #TEMPORARY CALL STATEMENT 
abuse_key = api_keys.get("abuse_key")
abuse_result = abuseipdb_lookup(pageip , abuse_key)

#WHOIS SECTION
#Calling the function to check 
print("\n[DEBUG] Calling WhoIS ...\n")
whois_result = whois_lookup(parsed_data["domain"])

