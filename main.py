from validator import valid_url
from parser import parse_url
from url_features import check_url_length
from rich.console import Console 
console=Console()

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
console.print("[Checking Length of the URL] " , style ="blue")
console.print("--------------------------", style="dim" )
if length_info["its_long"]:
    console.print("⚠️ Suspicious: URL is unusually long" , style="yellow")
else:
    console.print("✅ URL length looks normal", style="green")