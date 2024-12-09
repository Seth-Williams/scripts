import ipaddress
import requests
import sys
import argparse
from datetime import datetime
import csv
from tqdm import tqdm

def query_rdap(ip):
    """Query RDAP for IP information"""
    # Try ARIN first, then get redirect if needed
    try:
        response = requests.get(f"https://rdap.arin.net/registry/ip/{ip}", 
                              headers={'Accept': 'application/rdap+json'},
                              timeout=10)
        
        # Follow redirect if needed
        if response.status_code == 302:
            response = requests.get(response.headers['Location'], 
                                  headers={'Accept': 'application/rdap+json'},
                                  timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract organization name from entities
            org_name = "N/A"
            if 'entities' in data and len(data['entities']) > 0:
                for entity in data['entities']:
                    if 'roles' in entity and 'registrant' in entity['roles']:
                        org_name = entity.get('handle', "N/A")
                        if 'vcardArray' in entity:
                            for item in entity['vcardArray'][1:]:
                                if item[0] == 'fn':
                                    org_name = item[3]
                                    break
            
            return {
                'organization': org_name,
                'country': data.get('country', 'N/A'),
                'name': data.get('name', 'N/A'),
                'start_address': data.get('startAddress', 'N/A'),
                'end_address': data.get('endAddress', 'N/A')
            }
    except Exception as e:
        return {
            'organization': 'Error',
            'country': 'Error',
            'name': str(e),
            'start_address': 'N/A',
            'end_address': 'N/A'
        }

def process_file(input_file, output_file=None):
    """Process a file of IPs and output results"""
    if not output_file:
        output_file = f"ip_ownership_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    
    results = []
    
    try:
        with open(input_file, 'r') as f:
            entries = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found")
        sys.exit(1)
    
    print(f"\nProcessing {len(entries)} entries...")
    
    # Process each IP/subnet with progress bar
    for entry in tqdm(entries, desc="Querying RDAP"):
        try:
            # Handle both individual IPs and subnets
            network = ipaddress.ip_network(entry, strict=False)
            
            # For single IPs
            if network.num_addresses == 1:
                info = query_rdap(str(network.network_address))
                results.append({
                    'ip': str(network.network_address),
                    **info
                })
            # For subnets, just query first IP
            else:
                info = query_rdap(str(network.network_address))
                results.append({
                    'ip': f"{network.network_address}/{network.prefixlen}",
                    **info
                })
                
        except Exception as e:
            results.append({
                'ip': entry,
                'organization': 'Error',
                'country': 'Error',
                'name': f"Invalid IP/subnet: {str(e)}",
                'start_address': 'N/A',
                'end_address': 'N/A'
            })
    
    # Write results to CSV
    if results:
        fieldnames = ['ip', 'organization', 'country', 'name', 'start_address', 'end_address']
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(results)
        
        print(f"\nResults saved to: {output_file}")
        
        # Print summary to console
        print("\nSummary of results:")
        for result in results:
            print(f"\n{result['ip']}:")
            print(f"  Organization: {result['organization']}")
            print(f"  Country: {result['country']}")
            if result['name'] != 'N/A':
                print(f"  Network Name: {result['name']}")

def main():
    parser = argparse.ArgumentParser(description='Check ownership information for IP addresses and subnets.')
    parser.add_argument('input_file', help='Path to file containing IPs/subnets (one per line)')
    parser.add_argument('-o', '--output', help='Output CSV file path (optional)')
    args = parser.parse_args()
    
    process_file(args.input_file, args.output)

if __name__ == "__main__":
    main()