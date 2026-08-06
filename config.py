from dotenv import load_dotenv
import os 

def check_config():                                                             #Checks whether .env exists                                                    
    return os.path.exists(".env")
    
def setup_config():                                              #if not > adding the api keys to a new .env
    conscent=input("\nDo you want to enable Threat Intelligence (Y/N) \n > ")
    if conscent=="Y":
        vt_key = input("\nVirusTotal API Key (Press Enter to skip)\n> ")
        urlscan_key = input("\nURLScan API Key (Press Enter to skip)\n> ")
        abuse_key = input("\nAbuseIPDB API Key (Press Enter to skip)\n> ")
        gsb_key = input("\nGoogle Safe Browsing API Key (Press Enter to skip)\n> ")
    else:
        print("Threat Intelligence disabled ")
        vt_key = ""
        urlscan_key = ""
        abuse_key = ""
        gsb_key = ""
        

    with open(".env", "w") as file:
        file.write(f"VIRUSTOTAL_API_KEY={vt_key}\n")
        file.write(f"URLSCAN_API_KEY={urlscan_key}\n")
        file.write(f"ABUSEIPDB_API_KEY={abuse_key}\n")
        file.write(f"GOOGLE_SAFE_BROWSING_API_KEY={gsb_key}\n")
        
    print("\nConfiguration loaded successfully.\n")



def load_config():
    load_dotenv()
    return{ 
    "vt_key" : os.getenv("VIRUSTOTAL_API_KEY"),
    "urlscan_key" : os.getenv("URLSCAN_API_KEY"),                 #not the Old variable , after the key is load > a new variable is used 
    "abuse_key" : os.getenv("ABUSEIPDB_API_KEY"),
    "gsb_key" : os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")  
    }

def api_check(api_keys):
    return any(api_keys.values())
