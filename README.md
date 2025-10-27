# Advanced Subdomain Takeover Scanner

A comprehensive Python-based security tool for subdomain discovery and takeover vulnerability detection. This tool helps identify potentially vulnerable subdomains that could be subject to domain takeover attacks.

## 🔍 Overview

The Advanced Subdomain Takeover Scanner is designed for **defensive security testing** of your own domains. It combines multiple subdomain discovery tools with advanced vulnerability analysis to detect potential subdomain takeover risks across various cloud platforms.

## ✨ Features

- **Multi-Tool Subdomain Discovery**: Uses subfinder, amass, assetfinder, and findomain for comprehensive coverage
- **Comprehensive DNS Analysis**: Resolves A, AAAA, CNAME, MX, NS, and TXT records
- **HTTP/HTTPS Response Analysis**: Checks both protocols for takeover indicators
- **Vulnerability Detection**: Identifies vulnerabilities across 15+ cloud platforms
- **Multi-threaded Scanning**: Fast concurrent analysis with configurable thread counts
- **Detailed Reporting**: Generates JSON and HTML reports with actionable findings
- **Cloud Platform Support**: Detects vulnerabilities in:
  - AWS (S3, CloudFront, ELB)
  - Azure
  - GitHub/GitLab/Bitbucket Pages
  - Heroku
  - Netlify
  - Vercel
  - Shopify
  - WordPress
  - Fastly
  - Pantheon
  - Tumblr
  - Ghost
  - And more...

## 🚨 Security Notice

**IMPORTANT**: This tool is intended for:
- ✅ Testing your own domains
- ✅ Authorized security assessments
- ✅ Defensive security operations
- ✅ Bug bounty testing (with proper authorization)

**NEVER** use this tool for unauthorized security testing. Always ensure you have explicit written permission before scanning any domain.

## 📋 Prerequisites

### Required Tools

Before running the scanner, you need to install the following tools:

1. **subfinder**
   ```bash
   go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   ```

2. **amass**
   - Download from: https://github.com/OWASP/Amass
   - Or install via package manager

3. **assetfinder**
   ```bash
   go install github.com/tomnomnom/assetfinder@latest
   ```

4. **subjack**
   - Download from: https://github.com/haccer/subjack
   - Place `fingerprints.json` in `/path/to/subjack/`

5. **findomain** (optional)
   - Download from: https://github.com/Findomain/Findomain

### Python Dependencies

```bash
pip install dnspython requests
```

## 🔧 Installation

```bash
# Clone or download the repository
cd CyberSecurity

# Install Python dependencies
pip install -r requirements.txt

# Ensure all external tools are installed and in PATH
subfinder -version
amass -version
```

## 📖 Usage

### Basic Usage

```bash
python takeover_dns.py example.com
```

### Advanced Usage (with custom thread count)

```bash
python takeover_dns.py example.com 50
```

Where `50` is the number of threads to use (default: 50).

### Command Arguments

- `<domain>`: Target domain to scan (required)
- `<threads>`: Number of concurrent threads (optional, default: 50)

## 🔄 How It Works

The scanner operates in four phases:

### Phase 1: Subdomain Discovery
- Runs multiple subdomain discovery tools (subfinder, amass, assetfinder, findomain)
- Combines results to maximize coverage
- Saves discovered subdomains to file

### Phase 2: Subjack Analysis
- Runs subjack on discovered subdomains
- Uses fingerprinting to detect vulnerable services
- Identifies known takeover patterns

### Phase 3: Custom Vulnerability Analysis
- Performs DNS resolution for each subdomain
- Checks HTTP/HTTPS responses
- Analyzes content for takeover signatures
- Examines CNAME records for cloud service patterns

### Phase 4: Results and Reporting
- Generates comprehensive security report
- Saves results to JSON file
- Creates interactive HTML report
- Provides actionable recommendations

## 📊 Output Files

The scanner generates three types of output files:

1. **Subdomain List** (`{domain}_subdomains.txt`)
   - Plain text list of discovered subdomains
   - Useful for further analysis or manual inspection

2. **Detailed Results** (`{domain}_takeover_results.json`)
   - Complete JSON export with all findings
   - Includes DNS records, HTTP responses, vulnerability status
   - Suitable for integration with other tools

3. **Security Report** (`{domain}_security_report.html`)
   - Interactive HTML report
   - Categorized by vulnerability severity
   - Visual indicators for vulnerable subdomains
   - Includes recommendations and remediation steps

## 🔎 Vulnerability Detection

The scanner detects vulnerabilities by analyzing:

1. **DNS Records**: Checks CNAME records pointing to cloud services
2. **HTTP Responses**: Looks for error messages indicating unused resources
3. **Status Codes**: Identifies suspicious error codes (404, 403)
4. **Content Analysis**: Searches for platform-specific error messages
5. **Service Fingerprinting**: Matches against known vulnerable patterns

### Vulnerability Confidence Levels

- **HIGH**: Multiple indicators confirm takeover vulnerability
- **MEDIUM**: Some indicators suggest potential vulnerability
- **LOW**: Initial suspicion, requires manual verification

## 📝 Example Output

```
ADVANCED SUBDOMAIN TAKEOVER SCAN REPORT
================================================================================
Target Domain: example.com
Scan Date: 2024-01-15 10:30:45
Total Subdomains Discovered: 245
Total Subdomains Analyzed: 245
Vulnerable Subdomains: 3
Suspicious Subdomains: 12

🚨 CRITICAL - VULNERABLE SUBDOMAINS (3):
------------------------------------------------------------
  Subdomain: test.example.com
  Service: Heroku
  Confidence: HIGH
  Status Code: 404
  CNAME: app-name.herokuapp.com

⚠️  WARNING - SUSPICIOUS SUBDOMAINS (12):
------------------------------------------------------------
  Subdomain: staging.example.com
  Cloud Services: AWS S3
  CNAME: bucket.s3.amazonaws.com
```

## 🛠️ Troubleshooting

### Common Issues

**Issue**: `subfinder not found`
```bash
# Ensure Go is installed and subfinder is in your PATH
export PATH=$PATH:$(go env GOPATH)/bin
```

**Issue**: `amass not found`
```bash
# Install amass from GitHub releases
# https://github.com/OWASP/Amass/releases
```

**Issue**: SSL verification warnings
- The tool disables SSL verification by default for scanning purposes
- Ensure you're using this only in authorized testing scenarios

**Issue**: Timeout errors
- Large domains may require longer scan times
- Adjust thread count based on your system capabilities

## 🎯 Best Practices

1. **Run scans during off-peak hours** to minimize impact
2. **Use appropriate thread counts** based on target infrastructure
3. **Regular scanning**: Schedule monthly scans for your domains
4. **Monitor new subdomains**: Set up alerts for newly discovered subdomains
5. **Document findings**: Maintain a record of vulnerable subdomains and remediation actions

## 🔒 Remediation

If vulnerabilities are found:

1. **Immediate Action**: Investigate all VULNERABLE subdomains
2. **Remove Unused Records**: Delete DNS records for unused subdomains
3. **Implement Monitoring**: Set up automated subdomain monitoring
4. **Use CAA Records**: Prevent unauthorized certificate issuance
5. **Regular Audits**: Schedule periodic vulnerability scans

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. Areas for contribution:

- Additional cloud platform signatures
- Performance improvements
- Enhanced reporting features
- Better error handling

## 📄 License

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any domain.

## ⚠️ Disclaimer

This tool is designed for defensive security purposes. The authors are not responsible for misuse or damage caused by this tool. Always ensure you have explicit written permission before performing security scans.

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

## 🙏 Acknowledgments

This tool integrates and builds upon several excellent open-source security tools:
- [subfinder](https://github.com/projectdiscovery/subfinder)
- [amass](https://github.com/OWASP/Amass)
- [subjack](https://github.com/haccer/subjack)
- [assetfinder](https://github.com/tomnomnom/assetfinder)

---

**Remember**: Use this tool responsibly and only on domains you own or have explicit permission to test.

