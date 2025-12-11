# SAML PCAP Decoder

## Usage

```bash
python3 saml_pcap_decoder.py input.pcap output.csv
```

## Output CSV Columns

- `src_ip`, `src_port`, `dst_ip`, `dst_port` - Network 5-tuple info
- `method` - HTTP method (GET/POST)
- `host` - HTTP Host header
- `path` - Request path (truncated to 100 chars)
- `saml_type` - Either "SAMLRequest" or "SAMLResponse"
- `user_agent` - User-Agent header (for filtering scanners)
- `custom_headers` - X-Scanning-ID and other custom headers
- `xml` - Decoded SAML XML with newlines stripped

## Shell Script Analysis Examples

### 1. Filter out scanner traffic
```bash
# Remove rows with scanner User-Agents
grep -v "X-Scanning-ID" output.csv > filtered.csv
grep -v "Scanner/" filtered.csv > filtered2.csv
```

### 2. Find SAML Responses missing Assertion signatures (CVE-2025-59719)
```bash
# Look for <saml:Assertion without <ds:Signature nearby
grep "SAMLResponse" output.csv | grep "<saml:Assertion" | grep -v "<ds:Signature" > cve-2025-59719-candidates.csv
```

### 3. Find SAML Responses missing Response signatures (CVE-2025-59718)
```bash
# Look for <saml:Response without <ds:Signature at Response level
grep "SAMLResponse" output.csv | grep "<saml:Response" | grep -v "<ds:Signature" > cve-2025-59718-candidates.csv
```

### 4. Count unique source IPs
```bash
tail -n +2 output.csv | cut -d',' -f1 | sort | uniq -c | sort -rn
```

### 5. Extract just the XML for manual inspection
```bash
# Get XML column (11th field) for a specific IP
awk -F',' '$1=="192.168.1.100" {print $11}' output.csv > ip_192.168.1.100_xml.txt
```

### 6. Find unsigned Assertions with xmllint (pretty print)
```bash
# Extract XML, pretty print, and grep for missing signatures
tail -n +2 output.csv | cut -d',' -f11 | while read xml; do
    echo "$xml" | xmllint --format - 2>/dev/null
done | grep -B5 -A5 "<saml:Assertion"
```

### 7. Group by host
```bash
# Count SAML requests per host
tail -n +2 output.csv | cut -d',' -f6 | sort | uniq -c | sort -rn
```

### 8. Find specific vulnerable patterns
```bash
# CVE-2025-59719: Assertion without signature
awk -F',' '$11 ~ /<saml:Assertion/ && $11 !~ /<ds:Signature.*<\/saml:Assertion>/ {print}' output.csv > assertion-nosig.csv

# CVE-2025-59718: Response without signature wrapper
awk -F',' '$11 ~ /<saml:Response/ && $11 !~ /<saml:Response[^>]*>.*<ds:Signature/ {print}' output.csv > response-nosig.csv
```

## Advanced: Python post-processing for CVE attribution

```python
import csv
import re

def check_cve(xml):
    """Determine which CVE(s) apply"""
    cves = []
    
    # Check for Response signature issues
    response_match = re.search(r'<saml:Response[^>]*>(.*?)</saml:Response>', xml, re.DOTALL)
    if response_match:
        response_content = response_match.group(1)
        # Look for Signature before first Assertion
        assertion_pos = response_content.find('<saml:Assertion')
        if assertion_pos > 0:
            before_assertion = response_content[:assertion_pos]
            if '<ds:Signature' not in before_assertion:
                cves.append('CVE-2025-59718')
    
    # Check for Assertion signature issues
    assertion_matches = re.finditer(r'<saml:Assertion[^>]*>(.*?)</saml:Assertion>', xml, re.DOTALL)
    for match in assertion_matches:
        assertion_content = match.group(1)
        if '<ds:Signature' not in assertion_content:
            cves.append('CVE-2025-59719')
    
    return ','.join(cves) if cves else 'NONE'

# Read CSV and add CVE column
with open('output.csv', 'r') as infile, open('output_with_cves.csv', 'w', newline='') as outfile:
    reader = csv.DictReader(infile)
    fieldnames = reader.fieldnames + ['detected_cves']
    writer = csv.DictWriter(outfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for row in reader:
        row['detected_cves'] = check_cve(row['xml'])
        writer.writerow(row)
```

## Notes

- The script handles both GET requests with SAMLRequest in URI and POST requests with SAMLResponse in body
- XML is decoded from base64 and URL-decoded automatically
- Newlines are stripped for easier grep/awk processing
- For large pcaps (100K+ packets), processing may take a few minutes
