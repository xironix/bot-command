"""
RedLine Stealer parser plugin.

This module implements a parser for the RedLine stealer format.
"""

import re
import json
import os
from typing import Dict, Any, Tuple
from src.processing.stealer_plugins.base import StealerParserPlugin

class RedLineParser(StealerParserPlugin):
    """Parser for RedLine stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "redline_parser"
        self.value_multiplier = 1.2  # RedLine data is high value due to prevalence
        
        # RedLine specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"RedLine Stealer|RedLine Report|RedLine Logs|RedLine Results", re.IGNORECASE),
            "section_browser": re.compile(r"={2,}[\s]*(?:Browser|Browsers|Web)[\s]*={2,}", re.IGNORECASE),
            "section_system": re.compile(r"={2,}[\s]*(?:System|System Info|Machine|PC Info)[\s]*={2,}", re.IGNORECASE),
            "section_crypto": re.compile(r"={2,}[\s]*(?:Crypto|Wallets|Cryptocurrency)[\s]*={2,}", re.IGNORECASE),
            
            # Credential formats specific to RedLine
            "credentials": [
                # URL/Username/Password format
                re.compile(r"URL:[\s]*(https?://[^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Host/Username/Password format
                re.compile(r"Host:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Website/User/Pass format
                re.compile(r"Website:[\s]*([^\s\r\n]+)[\s\r\n]+User:[\s]*([^\s\r\n]+)[\s\r\n]+Pass:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # System info formats
            "system_info": [
                # OS version
                re.compile(r"OS:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Hardware ID
                re.compile(r"HWID:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Computer name
                re.compile(r"Computer Name:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Username
                re.compile(r"User(?:name)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Local IP
                re.compile(r"Local IP:[\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
                # Public IP
                re.compile(r"IP:[\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                # Crypto wallet headers
                re.compile(r"Wallet:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Bitcoin patterns
                re.compile(r"Bitcoin Core:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Ethereum patterns
                re.compile(r"Ethereum:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Generic wallet.dat reference
                re.compile(r"wallet\.dat:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Cookie patterns
            "cookies": [
                # Standard cookie format
                re.compile(r"Domain:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Alternate format
                re.compile(r"Host:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE)
            ]
        }
        
    def can_parse(self, message_data: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Check if this parser can handle the given message.
        
        Args:
            message_data: Message data including text and attachments
            
        Returns:
            Tuple of (can_parse, confidence_score)
        """
        text = message_data.get("text", "")
        if not text:
            return False, 0.0
            
        # Quick check for RedLine headers (high confidence)
        if self._patterns["header"].search(text):
            return True, 0.9
            
        # Check for section markers (medium confidence)
        section_score = 0.0
        if self._patterns["section_browser"].search(text):
            section_score += 0.2
        if self._patterns["section_system"].search(text):
            section_score += 0.2
        if self._patterns["section_crypto"].search(text):
            section_score += 0.2
            
        # Check for credential patterns (medium confidence)
        cred_score = 0.0
        for pattern in self._patterns["credentials"]:
            if pattern.search(text):
                cred_score += 0.3
                break
                
        # Combined score
        total_score = section_score + cred_score
        
        # If we have a reasonable confidence, return true
        return total_score >= self.confidence_threshold, total_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse RedLine stealer format message.
        
        Args:
            message_data: Message data including text and attachments
            
        Returns:
            Dictionary with extracted structured data
        """
        result = {
            "credentials": [],
            "cookies": [],
            "system_info": {},
            "crypto_wallets": [],
            "file_paths": [],
            "parsing_errors": []
        }
        
        text = message_data.get("text", "")
        if not text:
            return result
            
        # Extract credentials
        for pattern in self._patterns["credentials"]:
            for match in pattern.finditer(text):
                url_or_host, username, password = match.groups()
                
                # Extract domain from URL or use host directly
                if url_or_host.startswith(('http://', 'https://')):
                    domain = self.extract_domain_from_url(url_or_host)
                else:
                    domain = url_or_host
                    
                result["credentials"].append({
                    "url": url_or_host if url_or_host.startswith(('http://', 'https://')) else None,
                    "domain": domain,
                    "username": username,
                    "password": password
                })
                
        # Extract system information
        system_info = {}
        for pattern in self._patterns["system_info"]:
            match = pattern.search(text)
            if match:
                if pattern.pattern.startswith("OS:"):
                    system_info["os"] = match.group(1).strip()
                elif pattern.pattern.startswith("HWID:"):
                    system_info["hardware_id"] = match.group(1).strip()
                elif pattern.pattern.startswith("Computer Name:"):
                    system_info["computer_name"] = match.group(1).strip()
                elif pattern.pattern.startswith("User"):
                    system_info["username"] = match.group(1).strip()
                elif pattern.pattern.startswith("Local IP:"):
                    system_info["local_ip"] = match.group(1).strip()
                elif pattern.pattern.startswith("IP:"):
                    system_info["public_ip"] = match.group(1).strip()
                    
        if system_info:
            result["system_info"] = system_info
            
        # Extract cookies
        for pattern in self._patterns["cookies"]:
            for match in pattern.finditer(text):
                domain, cookie_value = match.groups()
                result["cookies"].append({
                    "domain": domain.strip(),
                    "value": cookie_value.strip()
                })
                
        # Extract crypto wallet information
        for pattern in self._patterns["crypto_wallets"]:
            for match in pattern.finditer(text):
                wallet_path = match.group(1).strip()
                wallet_type = "unknown"
                
                if pattern.pattern.startswith("Bitcoin"):
                    wallet_type = "bitcoin"
                elif pattern.pattern.startswith("Ethereum"):
                    wallet_type = "ethereum"
                elif pattern.pattern.startswith(r"wallet\.dat"):
                    wallet_type = "bitcoin"
                    
                result["crypto_wallets"].append({
                    "type": wallet_type,
                    "path": wallet_path
                })
                result["file_paths"].append(wallet_path)
                
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths"]:
                    if key in file_result and file_result[key]:
                        result[key].extend(file_result[key])
                        
                # Merge system info (dictionary)
                if file_result.get("system_info"):
                    result["system_info"].update(file_result["system_info"])
                    
                # Add any parsing errors
                if file_result.get("parsing_errors"):
                    result["parsing_errors"].extend(file_result["parsing_errors"])
            except Exception as e:
                result["parsing_errors"].append(f"Failed to parse attached file: {str(e)}")
                
        # Calculate value score
        result["value_score"] = self.calculate_value_score(result)
        
        return result
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a RedLine file.
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with extracted structured data
        """
        result = {
            "credentials": [],
            "cookies": [],
            "system_info": {},
            "crypto_wallets": [],
            "file_paths": [],
            "parsing_errors": []
        }
        
        if not os.path.exists(file_path):
            result["parsing_errors"].append(f"File does not exist: {file_path}")
            return result
            
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        try:
            # Handle different file types
            if ext == '.json':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    
                # Look for RedLine JSON structure
                if isinstance(data, dict):
                    # Extract credentials
                    if "credentials" in data and isinstance(data["credentials"], list):
                        for cred in data["credentials"]:
                            if isinstance(cred, dict):
                                url = cred.get("URL") or cred.get("url")
                                username = cred.get("Username") or cred.get("username")
                                password = cred.get("Password") or cred.get("password")
                                
                                if username and password:
                                    domain = None
                                    if url:
                                        domain = self.extract_domain_from_url(url)
                                    else:
                                        domain = self.extract_domain_from_username(username)
                                        
                                    result["credentials"].append({
                                        "url": url,
                                        "domain": domain,
                                        "username": username,
                                        "password": password
                                    })
                                    
                    # Extract cookies
                    if "cookies" in data and isinstance(data["cookies"], list):
                        for cookie in data["cookies"]:
                            if isinstance(cookie, dict):
                                domain = cookie.get("Domain") or cookie.get("domain") or cookie.get("Host") or cookie.get("host")
                                value = cookie.get("Value") or cookie.get("value") or cookie.get("Cookie") or cookie.get("cookie")
                                
                                if domain and value:
                                    result["cookies"].append({
                                        "domain": domain,
                                        "value": value
                                    })
                                    
                    # Extract system info
                    if "system" in data and isinstance(data["system"], dict):
                        system = data["system"]
                        sys_info = {}
                        
                        # Map common RedLine system info fields
                        mapping = {
                            "OS": "os", 
                            "os": "os",
                            "ComputerName": "computer_name",
                            "computerName": "computer_name",
                            "UserName": "username",
                            "userName": "username",
                            "HWID": "hardware_id",
                            "hwid": "hardware_id",
                            "IP": "public_ip",
                            "ip": "public_ip",
                            "LocalIP": "local_ip",
                            "localIP": "local_ip"
                        }
                        
                        for src, dest in mapping.items():
                            if src in system:
                                sys_info[dest] = system[src]
                                
                        if sys_info:
                            result["system_info"] = sys_info
                            
            elif ext in ['.txt', '.log']:
                # Process as plain text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Use the same parsing logic as for message text
                text_result = self.parse({"text": text})
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result
