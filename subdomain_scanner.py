import socket
import requests
from concurrent.futures import ThreadPoolExecutor

def is_subdomain_real(subdomain):
    """Check if a subdomain is real by attempting DNS resolution"""
    try:
        socket.gethostbyname(subdomain)
        return True
    except socket.gaierror:
        return False

def scan_subdomains(target_domain, wordlist_file="subdomains-top1mil-5000.txt"):
    """
    Scan for subdomains of the target domain using a wordlist
    and verify if they are real
    """
    real_subdomains = []
    
    try:
        # Open and read the wordlist file
        with open(wordlist_file, 'r') as file:
            subdomains = [line.strip() for line in file]
        
        print(f"Loaded {len(subdomains)} potential subdomains from wordlist")
        print(f"Scanning for subdomains of {target_domain}...")
        
        # Function to check a single subdomain
        def check_subdomain(subdomain_prefix):
            full_subdomain = f"{subdomain_prefix}.{target_domain}"
            if is_subdomain_real(full_subdomain):
                return full_subdomain
            return None
        
        # Use ThreadPoolExecutor for parallel scanning
        with ThreadPoolExecutor(max_workers=20) as executor:
            results = list(executor.map(check_subdomain, subdomains))
        
        # Filter out None results
        real_subdomains = [subdomain for subdomain in results if subdomain is not None]
        
        print(f"Found {len(real_subdomains)} real subdomains for {target_domain}")
        
    except FileNotFoundError:
        print(f"Error: Wordlist file '{wordlist_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    
    return real_subdomains

def main():
    """Main function to run the subdomain scanner"""
    target = input("Enter the target domain (e.g., example.com): ")
    wordlist = input("Enter the wordlist file path (default: subdomains-top1mil-5000.txt): ")
    
    if not wordlist:
        wordlist = "subdomains-top1mil-5000.txt"
    
    subdomains = scan_subdomains(target, wordlist)
    
    if subdomains:
        print("\nDiscovered Real Subdomains:")
        for subdomain in subdomains:
            print(subdomain)
    else:
        print("No real subdomains found.")

if __name__ == "__main__":
    main() 