# -------------------------------------------------------------------------------------------
#                           VirusTotal IOC Enrichment Tool
#
#   This command-line tool automates the process of enriching security indicators of
#   compromise (IOCs) by querying the VirusTotal API. It is designed for SOC analysts and
#   security researchers to quickly gain context on suspicious IP addresses and file hashes,
#   saving  valuable time during investigations.
#
# Author: [PAVLOS THEODOROPOULOS]
# -------------------------------------------------------------------------------------------

# Standard Library Imports
import os
import sys
import time
import re

# - ThirdParty Imports
# 'requests' is the standard library for making HTTP requests in Python.
# 'dotenv' is used to securely load environment variables from a .env file.
import requests
from dotenv import load_dotenv


VT_API_BASE_URL = "https://www.virustotal.com/api/v3/"
# The free VirusTotal API is limited to 4 requests per minute. 16 seconds gives a small buffer.
RATE_LIMIT_DELAY = 16

# Presentation
class bcolors:
    FAIL = '\033[91m'       # Red for malicious results
    OKGREEN = '\033[92m'    # Green for harmless results
    WARNING = '\033[93m'    # Yellow for suspicious results
    OKBLUE = '\033[94m'     # Blue for unknown or informational results
    ENDC = '\033[0m'        # This special code resetts the text color back to default
    BOLD = '\033[1m'

# - Configuration
def load_api_key():
    load_dotenv()
    api_key = os.environ.get("VT_API_KEY")

    # checks if the key exists and  is not just the placeholder text.
    if not api_key or api_key == "ENTER_YOUR_API_KEY_HERE":
        print(f"{bcolors.FAIL}Error:  VT_API_KEY not foud in the .env file.{bcolors.ENDC}")
        print("Create a .env file and add your API key.")
        sys.exit(1)
        
    return api_key

# - API Enrichment
def enrich_ip(ip_address, api_key):

    print(f"\n-- Enriching IP: {bcolors.BOLD}{ip_address}{bcolors.ENDC}")
    url = f"{VT_API_BASE_URL}ip_addresses/{ip_address}"
    # The API key is sent in the request header for authentication.
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        data = response.json()

        stats = data['data']['attributes']['last_analysis_stats']
        owner = data['data']['attributes'].get('as_owner', 'N/A')
        country = data['data']['attributes'].get('country', 'N/A')
        
        malicious_count = stats.get('malicious', 0)
        harmless_count = stats.get('harmless', 0)
        
        print(f"  Owner: {owner}")
        print(f"  Country: {country}")
        print(f"  Malicious Detections: {malicious_count}")
        print(f"  Harmless Detections: {harmless_count}")
        

        if malicious_count >= 5:
            print(f"  Status: {bcolors.FAIL}High Confidence Malicious{bcolors.ENDC}")
        elif malicious_count > 0:
            print(f"  Status: {bcolors.WARNING}Suspicious / Low Confidence{bcolors.ENDC}")
        elif harmless_count > 5:
            print(f"  Status: {bcolors.OKGREEN}Likely Harmless{bcolors.ENDC}")
        else:
            print(f"  Status: {bcolors.OKBLUE}Unknown / No Detections{bcolors.ENDC}")
            
    except requests.exceptions.HTTPError as e:
        print(f"  {bcolors.FAIL}Error: Received status code {e.response.status_code}{bcolors.ENDC}")
        print(f"  Details: {e.response.text}")
    except Exception as e:
        print(f"  {bcolors.FAIL}An unexpected error occurred: {e}{bcolors.ENDC}")


def enrich_hash(file_hash, api_key):

    print(f"\n-- Enriching Hash: {bcolors.BOLD}{file_hash}{bcolors.ENDC}")
    url = f"{VT_API_BASE_URL}files/{file_hash}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 404:
            print(f"  Status: {bcolors.OKBLUE}Not found in VirusTotal database.{bcolors.ENDC}")
            return

        response.raise_for_status()

        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        names = data['data']['attributes'].get('names', ['N/A'])
        
        malicious_count = stats.get('malicious', 0)
        
        print(f"  Common Names: {', '.join(names[:3])}")
        print(f"  Malicious Detections: {malicious_count}")
        
        if malicious_count > 5:
            print(f"  Status: {bcolors.FAIL}High Confidence Malicious{bcolors.ENDC}")
        elif malicious_count > 0:
            print(f"  Status: {bcolors.WARNING}Suspicious / Low Confidence{bcolors.ENDC}")
        else:
            print(f"  Status: {bcolors.OKGREEN}Confirmed Harmless / Benign{bcolors.ENDC}")

    except requests.exceptions.HTTPError as e:
        print(f"  {bcolors.FAIL}Error: Received status code {e.response.status_code}{bcolors.ENDC}")
        print(f"  Details: {e.response.text}")
    except Exception as e:
        print(f"  {bcolors.FAIL}An unexpected error occurred: {e}{bcolors.ENDC}")


def main():

    api_key = load_api_key()
    
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <filename_with_iocs>")
        sys.exit(1)
        
    ioc_filename = sys.argv[1]

    try:
        with open(ioc_filename, 'r') as f:
            # read all non empty lines from the fiile into a  list for processing.
            iocs = [line.strip() for line in f if line.strip()] 
    except FileNotFoundError:
        print(f"{bcolors.FAIL}Error: The file '{ioc_filename}' was not found.{bcolors.ENDC}")
        sys.exit(1)

    total_iocs = len(iocs)
    print(f"\nFound {bcolors.BOLD}{total_iocs}{bcolors.ENDC} IOCs to enrich.")

    # using a regular expression to validate an IPv4 address format.
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


    for index, ioc in enumerate(iocs):
        
        if ip_pattern.match(ioc):
            enrich_ip(ioc, api_key)
        else:
            enrich_hash(ioc, api_key)
        
        if index < total_iocs - 1:
            print(f"Waiting {RATE_LIMIT_DELAY} seconds to respect API rate limit")
            time.sleep(RATE_LIMIT_DELAY)

    print(f"\n{bcolors.OKGREEN}Enrichment complete.{bcolors.ENDC}")


if __name__ == "__main__":
    main()