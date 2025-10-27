#!/usr/bin/env python3
"""
Advanced Subdomain Takeover Scanner
Comprehensive subdomain discovery and takeover vulnerability detection
For defensive security testing of your own domains
"""

import subprocess
import sys
import os
import json
import requests
import dns.resolver
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import socket
import ssl
from datetime import datetime

class AdvancedSubdomainScanner:
    def __init__(self, domain, threads=50):
        self.domain = domain
        self.threads = threads
        self.subdomains = set()
        self.results = []
        self.lock = threading.Lock()
        
        # Comprehensive takeover signatures
        self.takeover_signatures = {
            'AWS S3': {
                'cname': ['s3.amazonaws.com', 's3-website', 's3.us-east-1.amazonaws.com'],
                'response': ['The specified bucket does not exist', 'NoSuchBucket', 'AccessDenied'],
                'status_codes': [404, 403]
            },
            'AWS CloudFront': {
                'cname': ['cloudfront.net'],
                'response': ['Bad Request', 'The request could not be satisfied'],
                'status_codes': [403, 400]
            },
            'AWS ELB': {
                'cname': ['elb.amazonaws.com', 'elb.us-east-1.amazonaws.com'],
                'response': ['No Response'],
                'status_codes': []
            },
            'Heroku': {
                'cname': ['herokuapp.com', 'herokussl.com'],
                'response': ['No such app', 'There\'s nothing here', 'herokucdn.com/error-pages/no-such-app.html'],
                'status_codes': [404]
            },
            'GitHub Pages': {
                'cname': ['github.io', 'githubusercontent.com'],
                'response': ['There isn\'t a GitHub Pages site here', 'For root URLs (like http://example.com/) you must provide an index.html file'],
                'status_codes': [404]
            },
            'GitLab Pages': {
                'cname': ['gitlab.io'],
                'response': ['The page you\'re looking for could not be found'],
                'status_codes': [404]
            },
            'Netlify': {
                'cname': ['netlify.com', 'netlify.app'],
                'response': ['Not Found', 'Page not found'],
                'status_codes': [404]
            },
            'Vercel': {
                'cname': ['vercel.app', 'now.sh'],
                'response': ['The deployment could not be found', 'DEPLOYMENT_NOT_FOUND'],
                'status_codes': [404]
            },
            'Azure': {
                'cname': ['azurewebsites.net', 'azure.com', 'cloudapp.azure.com'],
                'response': ['Web App - Unavailable', 'This web app has been stopped'],
                'status_codes': [404]
            },
            'Fastly': {
                'cname': ['fastly.com', 'fastlylb.net'],
                'response': ['Fastly error: unknown domain', 'Please check that this domain has been added to a service'],
                'status_codes': [404]
            },
            'Pantheon': {
                'cname': ['pantheonsite.io'],
                'response': ['The gods are wise', '404 error unknown site'],
                'status_codes': [404]
            },
            'Tumblr': {
                'cname': ['domains.tumblr.com'],
                'response': ['Whatever you were looking for doesn\'t currently exist at this address'],
                'status_codes': [404]
            },
            'WordPress': {
                'cname': ['wordpress.com'],
                'response': ['Do you want to register'],
                'status_codes': [404]
            },
            'Ghost': {
                'cname': ['ghost.io'],
                'response': ['The thing you were looking for is no longer here'],
                'status_codes': [404]
            },
            'Shopify': {
                'cname': ['myshopify.com'],
                'response': ['Sorry, this shop is currently unavailable', 'Only one step left!'],
                'status_codes': [404]
            },
            'Bitbucket': {
                'cname': ['bitbucket.io'],
                'response': ['Repository not found'],
                'status_codes': [404]
            }
        }

    def run_subfinder(self):
        """Enhanced subfinder execution with multiple sources"""
        print(f"[*] Running subfinder on {self.domain} ...")
        cmd = [
            "subfinder", 
            "-d", self.domain, 
            "-silent", 
            "-all",
            "-recursive",
            "-t", "100"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
            found_subs = set(line.strip() for line in result.stdout.splitlines() if line.strip())
            print(f"[+] Subfinder found {len(found_subs)} subdomains")
            return found_subs
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running subfinder: {e}")
            return set()
        except FileNotFoundError:
            print("❌ subfinder not found. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return set()
        except subprocess.TimeoutExpired:
            print("❌ Subfinder timed out after 10 minutes")
            return set()

    def run_amass(self):
        """Enhanced amass execution"""
        print(f"[*] Running amass on {self.domain} ...")
        cmd = [
            "amass", "enum", 
            "-d", self.domain, 
            "-silent",
            "-active",
            "-brute"
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=900)
            found_subs = set(line.strip() for line in result.stdout.splitlines() if line.strip())
            print(f"[+] Amass found {len(found_subs)} subdomains")
            return found_subs
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running amass: {e}")
            return set()
        except FileNotFoundError:
            print("❌ amass not found. Install from: https://github.com/OWASP/Amass")
            return set()
        except subprocess.TimeoutExpired:
            print("❌ Amass timed out after 15 minutes")
            return set()

    def run_assetfinder(self):
        """Run assetfinder for additional subdomain discovery"""
        print(f"[*] Running assetfinder on {self.domain} ...")
        cmd = ["assetfinder", "--subs-only", self.domain]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            found_subs = set(line.strip() for line in result.stdout.splitlines() if line.strip())
            print(f"[+] Assetfinder found {len(found_subs)} subdomains")
            return found_subs
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running assetfinder: {e}")
            return set()
        except FileNotFoundError:
            print("⚠️  assetfinder not found. Install: go install github.com/tomnomnom/assetfinder@latest")
            return set()
        except subprocess.TimeoutExpired:
            print("❌ Assetfinder timed out")
            return set()

    def run_findomain(self):
        """Run findomain for additional subdomain discovery"""
        print(f"[*] Running findomain on {self.domain} ...")
        cmd = ["findomain", "-t", self.domain, "-q"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=300)
            found_subs = set(line.strip() for line in result.stdout.splitlines() if line.strip())
            print(f"[+] Findomain found {len(found_subs)} subdomains")
            return found_subs
        except subprocess.CalledProcessError as e:
            print(f"❌ Error running findomain: {e}")
            return set()
        except FileNotFoundError:
            print("⚠️  findomain not found. Install from: https://github.com/Findomain/Findomain")
            return set()
        except subprocess.TimeoutExpired:
            print("❌ Findomain timed out")
            return set()

    def run_subjack(self, subdomains_file):
        """Run subjack for subdomain takeover detection"""
        print(f"[*] Running subjack on discovered subdomains...")
        cmd = [
            "subjack",
            "-w", subdomains_file,
            "-t", str(self.threads),
            "-timeout", "30",
            "-ssl",
            "-c", "/path/to/subjack/fingerprints.json",  # Update this path
            "-v"
        ]
        
        subjack_results = []
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=1800)  # 30 minute timeout
            
            if stdout:
                print("[+] Subjack output:")
                for line in stdout.splitlines():
                    if "[VULNERABLE]" in line or "VULNERABLE" in line:
                        print(f"🚨 {line}")
                        subjack_results.append(line)
                    else:
                        print(f"  {line}")
            
            if stderr and "error" in stderr.lower():
                print(f"[!] Subjack warnings: {stderr}")
                
        except subprocess.TimeoutExpired:
            print("❌ Subjack timed out after 30 minutes")
            process.kill()
        except FileNotFoundError:
            print("❌ subjack not found. Install from: https://github.com/haccer/subjack")
        except Exception as e:
            print(f"❌ Error running subjack: {e}")
        
        return subjack_results

    def resolve_dns(self, subdomain):
        """Comprehensive DNS resolution"""
        dns_info = {
            'subdomain': subdomain,
            'a_records': [],
            'aaaa_records': [],
            'cname_records': [],
            'mx_records': [],
            'ns_records': [],
            'txt_records': [],
            'resolvable': False
        }
        
        try:
            # A records
            try:
                answers = dns.resolver.resolve(subdomain, 'A')
                dns_info['a_records'] = [str(answer) for answer in answers]
                dns_info['resolvable'] = True
            except:
                pass
            
            # AAAA records
            try:
                answers = dns.resolver.resolve(subdomain, 'AAAA')
                dns_info['aaaa_records'] = [str(answer) for answer in answers]
            except:
                pass
            
            # CNAME records
            try:
                answers = dns.resolver.resolve(subdomain, 'CNAME')
                dns_info['cname_records'] = [str(answer) for answer in answers]
                dns_info['resolvable'] = True
            except:
                pass
            
            # MX records
            try:
                answers = dns.resolver.resolve(subdomain, 'MX')
                dns_info['mx_records'] = [str(answer) for answer in answers]
            except:
                pass
            
            # NS records
            try:
                answers = dns.resolver.resolve(subdomain, 'NS')
                dns_info['ns_records'] = [str(answer) for answer in answers]
            except:
                pass
            
            # TXT records
            try:
                answers = dns.resolver.resolve(subdomain, 'TXT')
                dns_info['txt_records'] = [str(answer) for answer in answers]
            except:
                pass
                
        except Exception as e:
            dns_info['error'] = str(e)
        
        return dns_info

    def check_http_response(self, subdomain):
        """Enhanced HTTP response checking"""
        http_info = {
            'subdomain': subdomain,
            'http_status': None,
            'https_status': None,
            'http_response': '',
            'https_response': '',
            'headers': {},
            'redirect_chain': [],
            'vulnerable': False,
            'vulnerability_type': None,
            'confidence': 'LOW'
        }
        
        # Check both HTTP and HTTPS
        for protocol in ['https', 'http']:
            try:
                url = f"{protocol}://{subdomain}"
                response = requests.get(
                    url, 
                    timeout=15, 
                    allow_redirects=True,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if protocol == 'https':
                    http_info['https_status'] = response.status_code
                    http_info['https_response'] = response.text[:5000]  # First 5k chars
                else:
                    http_info['http_status'] = response.status_code
                    http_info['http_response'] = response.text[:5000]
                
                http_info['headers'] = dict(response.headers)
                http_info['redirect_chain'] = [r.url for r in response.history]
                
                # Check for takeover signatures
                content_lower = response.text.lower()
                for service, signatures in self.takeover_signatures.items():
                    # Check response content
                    for signature in signatures['response']:
                        if signature.lower() in content_lower:
                            http_info['vulnerable'] = True
                            http_info['vulnerability_type'] = service
                            http_info['confidence'] = 'HIGH'
                            break
                    
                    # Check status codes
                    if response.status_code in signatures.get('status_codes', []):
                        if not http_info['vulnerable']:
                            http_info['vulnerable'] = True
                            http_info['vulnerability_type'] = service
                            http_info['confidence'] = 'MEDIUM'
                
                break  # If we get a response, no need to try the other protocol
                
            except requests.exceptions.RequestException as e:
                continue
        
        return http_info

    def check_takeover_vulnerability(self, subdomain):
        """Comprehensive takeover vulnerability check"""
        print(f"[*] Analyzing {subdomain}")
        
        # DNS resolution
        dns_info = self.resolve_dns(subdomain)
        
        # Skip if not resolvable
        if not dns_info['resolvable']:
            return None
        
        # HTTP response check
        http_info = self.check_http_response(subdomain)
        
        # Check for cloud service patterns in CNAME
        cloud_services = []
        for cname in dns_info.get('cname_records', []):
            for service, signatures in self.takeover_signatures.items():
                for pattern in signatures['cname']:
                    if pattern in cname.lower():
                        cloud_services.append(service)
                        break
        
        # Determine vulnerability status
        vulnerability_status = 'SAFE'
        if http_info['vulnerable']:
            vulnerability_status = 'VULNERABLE'
        elif cloud_services:
            vulnerability_status = 'SUSPICIOUS'
        
        result = {
            'subdomain': subdomain,
            'dns_info': dns_info,
            'http_info': http_info,
            'cloud_services': cloud_services,
            'vulnerability_status': vulnerability_status,
            'timestamp': datetime.now().isoformat()
        }
        
        with self.lock:
            self.results.append(result)
        
        if vulnerability_status == 'VULNERABLE':
            print(f"🚨 VULNERABLE: {subdomain} - {http_info['vulnerability_type']}")
        elif vulnerability_status == 'SUSPICIOUS':
            print(f"⚠️  SUSPICIOUS: {subdomain} - {', '.join(cloud_services)}")
        
        return result

    def save_subdomains(self, filename):
        """Save discovered subdomains to file"""
        with open(filename, 'w') as f:
            for subdomain in sorted(self.subdomains):
                f.write(f"{subdomain}\n")
        print(f"[+] Saved {len(self.subdomains)} subdomains to {filename}")

    def save_results(self, filename):
        """Save detailed results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] Detailed results saved to {filename}")

    def generate_report(self):
        """Generate comprehensive security report"""
        vulnerable = [r for r in self.results if r['vulnerability_status'] == 'VULNERABLE']
        suspicious = [r for r in self.results if r['vulnerability_status'] == 'SUSPICIOUS']
        
        print("\n" + "="*80)
        print("ADVANCED SUBDOMAIN TAKEOVER SCAN REPORT")
        print("="*80)
        print(f"Target Domain: {self.domain}")
        print(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Total Subdomains Discovered: {len(self.subdomains)}")
        print(f"Total Subdomains Analyzed: {len(self.results)}")
        print(f"Vulnerable Subdomains: {len(vulnerable)}")
        print(f"Suspicious Subdomains: {len(suspicious)}")
        
        if vulnerable:
            print(f"\n🚨 CRITICAL - VULNERABLE SUBDOMAINS ({len(vulnerable)}):")
            print("-" * 60)
            for result in vulnerable:
                print(f"  Subdomain: {result['subdomain']}")
                print(f"  Service: {result['http_info']['vulnerability_type']}")
                print(f"  Confidence: {result['http_info']['confidence']}")
                print(f"  Status Code: {result['http_info'].get('https_status') or result['http_info'].get('http_status')}")
                if result['dns_info']['cname_records']:
                    print(f"  CNAME: {', '.join(result['dns_info']['cname_records'])}")
                print()
        
        if suspicious:
            print(f"\n⚠️  WARNING - SUSPICIOUS SUBDOMAINS ({len(suspicious)}):")
            print("-" * 60)
            for result in suspicious:
                print(f"  Subdomain: {result['subdomain']}")
                print(f"  Cloud Services: {', '.join(result['cloud_services'])}")
                if result['dns_info']['cname_records']:
                    print(f"  CNAME: {', '.join(result['dns_info']['cname_records'])}")
                print()
        
        print("="*80)
        
        # Recommendations
        if vulnerable or suspicious:
            print("\n📋 RECOMMENDATIONS:")
            print("-" * 30)
            print("1. Immediately investigate all VULNERABLE subdomains")
            print("2. Remove or properly configure DNS records for unused subdomains")
            print("3. Implement monitoring for new subdomain creation")
            print("4. Regular subdomain takeover scans (monthly)")
            print("5. Use CAA records to prevent unauthorized certificate issuance")

    def run_comprehensive_scan(self):
        """Execute the complete subdomain takeover scan"""
        print(f"🔍 Advanced Subdomain Takeover Scanner")
        print(f"Target: {self.domain}")
        print(f"Threads: {self.threads}")
        print("=" * 60)
        
        # Phase 1: Subdomain Discovery
        print("\n[PHASE 1] Subdomain Discovery")
        print("-" * 40)
        
        self.subdomains.update(self.run_subfinder())
        self.subdomains.update(self.run_amass())
        self.subdomains.update(self.run_assetfinder())
        self.subdomains.update(self.run_findomain())
        
        if not self.subdomains:
            print("❌ No subdomains discovered. Exiting.")
            return
        
        print(f"\n[+] Total unique subdomains discovered: {len(self.subdomains)}")
        
        # Save subdomains for subjack
        subdomains_file = f"{self.domain}_subdomains.txt"
        self.save_subdomains(subdomains_file)
        
        # Phase 2: Subjack Analysis
        print(f"\n[PHASE 2] Subjack Analysis")
        print("-" * 40)
        subjack_results = self.run_subjack(subdomains_file)
        
        # Phase 3: Custom Vulnerability Analysis
        print(f"\n[PHASE 3] Custom Vulnerability Analysis")
        print("-" * 40)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.check_takeover_vulnerability, sub) for sub in self.subdomains]
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"❌ Error analyzing subdomain: {e}")
        
        # Phase 4: Results and Reporting
        print(f"\n[PHASE 4] Results and Reporting")
        print("-" * 40)
        
        results_file = f"{self.domain}_takeover_results.json"
        self.save_results(results_file)
        self.generate_report()
        
        # Generate HTML Report
        self.generate_html_report(results_file)
        
        print(f"\n✅ Scan completed successfully!")
        print(f"📁 Files generated:")
        print(f"  - {subdomains_file} (discovered subdomains)")
        print(f"  - {results_file} (detailed JSON results)")
        print(f"  - {self.domain}_security_report.html (interactive HTML report)")
        
    def generate_html_report(self, results_file):
        """Generate professional HTML security report"""
        try:
            from html_report_generator import HTMLReportGenerator
            
            print("[*] Generating HTML security report...")
            generator = HTMLReportGenerator(results_file, self.domain)
            html_content = generator.generate_html_report()
            
            html_filename = f"{self.domain}_security_report.html"
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            print(f"[+] HTML report generated: {html_filename}")
            
            # Optionally open in browser
            import webbrowser
            import os
            file_path = os.path.abspath(html_filename)
            try:
                webbrowser.open(f"file://{file_path}")
                print(f"[+] Report opened in browser")
            except:
                print(f"[!] Could not open browser. Manual open: file://{file_path}")
                
        except ImportError:
            print("[!] HTML report generator not found. Please ensure html_report_generator.py is in the same directory.")
        except Exception as e:
            print(f"[!] Error generating HTML report: {e}")

def main():
    if len(sys.argv) < 2:
        print("Advanced Subdomain Takeover Scanner")
        print("=" * 40)
        print(f"Usage: python {sys.argv[0]} <domain> [threads]")
        print(f"Example: python {sys.argv[0]} example.com 50")
        print("\nRequired Tools:")
        print("- subfinder: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("- amass: https://github.com/OWASP/Amass")
        print("- subjack: https://github.com/haccer/subjack")
        print("- assetfinder: go install github.com/tomnomnom/assetfinder@latest")
        print("- findomain: https://github.com/Findomain/Findomain")
        sys.exit(1)

    domain = sys.argv[1].strip()
    threads = int(sys.argv[2]) if len(sys.argv) > 2 else 50
    
    # Validate domain
    if not domain or '.' not in domain:
        print("❌ Please provide a valid domain name")
        sys.exit(1)
    
    # Create scanner instance
    scanner = AdvancedSubdomainScanner(domain, threads)
    
    try:
        scanner.run_comprehensive_scan()
    except KeyboardInterrupt:
        print(f"\n❌ Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()