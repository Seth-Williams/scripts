import ipaddress
import requests
import dns.resolver
import dns.reversename
import concurrent.futures
import time
from typing import List, Dict
import csv
from datetime import datetime
import argparse
import sys

class IPOwnershipChecker:
    def __init__(self, rate_limit: int = 1):
        """
        Initialize the checker with rate limiting to respect API limits
        rate_limit: seconds between API calls
        """
        self.rate_limit = rate_limit
        self.rdap_endpoints = {
            'ARIN': 'https://rdap.arin.net/registry/ip/',
            'RIPE': 'https://rdap.db.ripe.net/ip/',
            'APNIC': 'https://rdap.apnic.net/ip/',
            'LACNIC': 'https://rdap.lacnic.net/rdap/ip/',
            'AFRINIC': 'https://rdap.afrinic.net/rdap/ip/'
        }

    def _get_reverse_dns(self, ip: str) -> str:
        """Get reverse DNS record for an IP"""
        try:
            reverse_name = dns.reversename.from_address(ip)
            answers = dns.resolver.resolve(reverse_name, "PTR")
            return str(answers[0])
        except Exception:
            return "No reverse DNS record found"

    def _query_rdap(self, ip: str) -> Dict:
        """Query RDAP servers for IP information"""
        for registry, endpoint in self.rdap_endpoints.items():
            try:
                response = requests.get(f"{endpoint}{ip}", timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        'registry': registry,
                        'name': data.get('name', 'N/A'),
                        'organization': data.get('entities', [{}])[0].get('vcardArray', [[]])[1].get('org', 'N/A'),
                        'country': data.get('country', 'N/A'),
                        'start_address': data.get('startAddress', 'N/A'),
                        'end_address': data.get('endAddress', 'N/A')
                    }
            except Exception:
                continue
            time.sleep(self.rate_limit)
        return {'registry': 'Unknown', 'name': 'N/A', 'organization': 'N/A', 'country': 'N/A'}

    def process_ip(self, ip: str) -> Dict:
        """Process a single IP address"""
        try:
            rdap_info = self._query_rdap(ip)
            reverse_dns = self._get_reverse_dns(ip)
            return {
                'ip': ip,
                'reverse_dns': reverse_dns,
                **rdap_info
            }
        except Exception as e:
            return {
                'ip': ip,
                'error': str(e)
            }

    def process_file(self, input_file: str, output_file: str = None) -> List[Dict]:
        """
        Process a file containing IPs and subnets
        input_file: path to file with one IP/subnet per line
        output_file: optional CSV output file path
        """
        results = []
        
        if not output_file:
            output_file = f"ip_ownership_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

        try:
            with open(input_file, 'r') as f:
                entries = f.read().splitlines()
        except FileNotFoundError:
            print(f"Error: File '{input_file}' not found")
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {str(e)}")
            sys.exit(1)

        # Process each entry (IP or subnet)
        for entry in entries:
            try:
                # Handle both individual IPs and subnets
                network = ipaddress.ip_network(entry.strip(), strict=False)
                if network.num_addresses == 1:
                    result = self.process_ip(str(network.network_address))
                    results.append(result)
                else:
                    # For subnets, process first and last IP
                    first_ip = self.process_ip(str(network.network_address))
                    last_ip = self.process_ip(str(network[-1]))
                    results.extend([first_ip, last_ip])
            except Exception as e:
                results.append({
                    'ip': entry,
                    'error': f"Invalid IP/subnet format: {str(e)}"
                })
            time.sleep(self.rate_limit)

        # Write results to CSV
        if results:
            fieldnames = results[0].keys()
            with open(output_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            print(f"\nResults saved to: {output_file}")

        return results

def main():
    parser = argparse.ArgumentParser(description='Check ownership information for IP addresses and subnets.')
    parser.add_argument('input_file', help='Path to file containing IPs/subnets (one per line)')
    parser.add_argument('-o', '--output', help='Output CSV file path (optional)')
    parser.add_argument('-r', '--rate-limit', type=int, default=1,
                      help='Rate limit in seconds between API calls (default: 1)')
    args = parser.parse_args()

    checker = IPOwnershipChecker(rate_limit=args.rate_limit)
    results = checker.process_file(args.input_file, args.output)

    # Print results
    for result in results:
        print(f"\nResults for {result['ip']}:")
        for key, value in result.items():
            if key != 'ip':
                print(f"{key}: {value}")

if __name__ == "__main__":
    main()