#!/usr/bin/env python3
"""
Simple test script to check Elasticsearch connectivity.
"""

import sys
import socket
import ssl
import requests
from urllib.parse import urlparse

# URL to test - default is HTTPS
url = "https://localhost:9200"
if len(sys.argv) > 1:
    url = sys.argv[1]

print(f"Testing connection to Elasticsearch at: {url}")

# Parse URL
parsed_url = urlparse(url)
hostname = parsed_url.hostname
port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)
is_https = parsed_url.scheme == 'https'

# Test 1: Basic socket connection
try:
    print(f"\n=== Test 1: Basic socket connection to {hostname}:{port} ===")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((hostname, port))
    s.close()
    print(f"SUCCESS: Socket connection to {hostname}:{port} successful")
except Exception as e:
    print(f"FAILED: Socket connection to {hostname}:{port} failed: {str(e)}")
    if port != 9200:
        try:
            alt_port = 9200
            print(f"\nTrying alternative port {hostname}:{alt_port}...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((hostname, alt_port))
            s.close()
            print(f"SUCCESS: Socket connection to {hostname}:{alt_port} successful")
            print(f"RECOMMENDATION: Try using port 9200 explicitly in your URL")
        except Exception as alt_e:
            print(f"FAILED: Alternative socket connection to {hostname}:9200 also failed: {str(alt_e)}")

# Test 2: HTTP request with certificate verification disabled
try:
    print(f"\n=== Test 2: HTTP request to {url} (verify=False) ===")
    response = requests.get(url, verify=False, timeout=5)
    print(f"SUCCESS: HTTP request succeeded with status code {response.status_code}")
    print(f"Response: {response.text[:100]}...")
except Exception as e:
    print(f"FAILED: HTTP request failed: {str(e)}")
    
    # If HTTPS failed, try HTTP
    if is_https:
        http_url = url.replace("https://", "http://")
        try:
            print(f"\nTrying HTTP instead of HTTPS: {http_url}")
            response = requests.get(http_url, timeout=5)
            print(f"SUCCESS: HTTP request succeeded with status code {response.status_code}")
            print(f"Response: {response.text[:100]}...")
            print(f"RECOMMENDATION: Try using HTTP instead of HTTPS in your URL")
        except Exception as http_e:
            print(f"FAILED: HTTP request also failed: {str(http_e)}")

# Test 3: Creating a custom SSL context
if is_https:
    try:
        print(f"\n=== Test 3: HTTPS request with custom SSL context ===")
        # Create a custom SSL context
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Try with the requests library using this context
        from requests.adapters import HTTPAdapter
        from requests.packages.urllib3.poolmanager import PoolManager
        
        class SSLAdapter(HTTPAdapter):
            def __init__(self, ssl_context=None, **kwargs):
                self.ssl_context = ssl_context
                super().__init__(**kwargs)
                
            def init_poolmanager(self, connections, maxsize, block=False):
                self.poolmanager = PoolManager(
                    num_pools=connections,
                    maxsize=maxsize,
                    block=block,
                    ssl_context=self.ssl_context
                )
                
        session = requests.Session()
        session.mount('https://', SSLAdapter(context))
        
        response = session.get(url, timeout=5)
        print(f"SUCCESS: HTTPS request with custom SSL context succeeded with status code {response.status_code}")
        print(f"Response: {response.text[:100]}...")
    except Exception as e:
        print(f"FAILED: HTTPS request with custom SSL context failed: {str(e)}")

print("\nRecommendations:")
print("1. Make sure Elasticsearch is running and accessible from this machine")
print("2. Check if the hostname and port are correct")
print("3. For HTTPS issues, you might need to configure the SSL context or use HTTP instead")
print("4. If you're using Docker, make sure the ports are properly mapped to the host")
print("5. Check the Elasticsearch logs for any connection errors") 