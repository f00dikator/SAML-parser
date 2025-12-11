#!/usr/bin/env python3
"""
SAML PCAP Decoder
Extracts SAMLRequest and SAMLResponse parameters from pcap files,
decodes base64, strips newlines, and outputs to CSV for analysis.
"""

import base64
import csv
import sys
import re
from urllib.parse import unquote
from scapy.all import rdpcap, TCP, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse

def decode_saml(b64_string):
    """Decode base64 SAML and strip newlines"""
    try:
        # URL decode first (in case it's URL encoded)
        decoded_url = unquote(b64_string)
        # Base64 decode
        xml_bytes = base64.b64decode(decoded_url)
        # Convert to string and strip all newlines/carriage returns
        xml_str = xml_bytes.decode('utf-8', errors='ignore')
        xml_str = xml_str.replace('\n', '').replace('\r', '')
        return xml_str
    except Exception as e:
        return f"ERROR_DECODING: {str(e)}"

def extract_saml_from_packet(packet):
    """Extract SAML data from HTTP packet"""
    results = []
    
    if packet.haslayer(HTTPRequest):
        http_layer = packet[HTTPRequest]
        
        # Get basic packet info
        src_ip = packet[1].src if packet.haslayer('IP') else "unknown"
        dst_ip = packet[1].dst if packet.haslayer('IP') else "unknown"
        src_port = packet[TCP].sport if packet.haslayer(TCP) else 0
        dst_port = packet[TCP].dport if packet.haslayer(TCP) else 0
        
        # Get HTTP details
        method = http_layer.Method.decode('utf-8', errors='ignore') if http_layer.Method else ""
        host = http_layer.Host.decode('utf-8', errors='ignore') if http_layer.Host else ""
        path = http_layer.Path.decode('utf-8', errors='ignore') if http_layer.Path else ""
        
        # Get User-Agent
        user_agent = ""
        if http_layer.User_Agent:
            user_agent = http_layer.User_Agent.decode('utf-8', errors='ignore')
        
        # Get custom headers (like X-Scanning-ID)
        custom_headers = ""
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            x_scanning = re.search(r'X-Scanning-ID:\s*([^\r\n]+)', raw_data, re.IGNORECASE)
            if x_scanning:
                custom_headers = f"X-Scanning-ID: {x_scanning.group(1)}"
        
        # Look for SAMLRequest in URI
        saml_request_match = re.search(r'SAMLRequest=([^&\s]+)', path)
        if saml_request_match:
            saml_b64 = saml_request_match.group(1)
            xml = decode_saml(saml_b64)
            results.append({
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'method': method,
                'host': host,
                'path': path[:100],  # Truncate long paths
                'saml_type': 'SAMLRequest',
                'user_agent': user_agent,
                'custom_headers': custom_headers,
                'xml': xml
            })
        
        # Look for SAMLResponse in POST body
        if packet.haslayer(Raw) and method == b'POST':
            raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
            saml_response_match = re.search(r'SAMLResponse=([^&\s]+)', raw_data)
            if saml_response_match:
                saml_b64 = saml_response_match.group(1)
                xml = decode_saml(saml_b64)
                results.append({
                    'src_ip': src_ip,
                    'src_port': src_port,
                    'dst_ip': dst_ip,
                    'dst_port': dst_port,
                    'method': method,
                    'host': host,
                    'path': path[:100],
                    'saml_type': 'SAMLResponse',
                    'user_agent': user_agent,
                    'custom_headers': custom_headers,
                    'xml': xml
                })
    
    return results

def process_pcap(pcap_file, output_csv):
    """Process pcap file and write results to CSV"""
    print(f"[*] Reading pcap: {pcap_file}")
    
    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"[!] Error reading pcap: {e}")
        return
    
    print(f"[*] Processing {len(packets)} packets...")
    
    all_results = []
    for i, packet in enumerate(packets):
        if (i + 1) % 1000 == 0:
            print(f"[*] Processed {i + 1} packets...")
        
        results = extract_saml_from_packet(packet)
        all_results.extend(results)
    
    print(f"[*] Found {len(all_results)} SAML messages")
    
    if all_results:
        print(f"[*] Writing to CSV: {output_csv}")
        with open(output_csv, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'method', 
                         'host', 'path', 'saml_type', 'user_agent', 'custom_headers', 'xml']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in all_results:
                writer.writerow(result)
        
        print(f"[+] Done! Results written to {output_csv}")
    else:
        print("[!] No SAML messages found in pcap")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 saml_pcap_decoder.py <input.pcap> <output.csv>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_csv = sys.argv[2]
    
    process_pcap(pcap_file, output_csv)
