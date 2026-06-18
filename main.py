from validator import valid_url
from parser import parse_url
from url_features import check_url_length


# TOOL INTRO 
def welcome():
    print("=" * 50)
    print("        PHISHING URL ANALYZER")
    print(" Just Enter the URL and Let me do my work for you  ")
    print("=" * 50)

# FETCHING THE URL 
def get_url():
    url = input("Enter a URL: ").strip().lower()
    return url


welcome()

user_url=get_url()

if valid_url(user_url):
    print("\nAnalysing ...")
    parsed_data=parse_url(user_url)

    print("\nParsed URL Information")
    print("-" * 30)
    print("Scheme :", parsed_data["scheme"])
    print("Domain :", parsed_data["domain"])
    print("Subdomain :", parsed_data["subdomain"])
    print("Path   :", parsed_data["path"])
    print("Query  :", parsed_data["query"])
    print("-" * 30)

else:
    print("Invalid URL ")

# Checking URL Features
# Checking URL length

length_info= check_url_length(user_url)

#Printing the URL Features 
print("Checking Length of the URL ")
print("--------------------------" )
if length_info["its_long"]:
    print("⚠️ Suspicious: URL is unusually long")
else:
    print("✅ URL length looks normal")