"""
Lumma Stealer parser plugin.

This module implements a parser for the Lumma stealer format (LummaC2).
Lumma is a newer stealer with advanced features like cookie regeneration.
"""

import re
import json
import os
import binascii
from typing import Dict, Any, Tuple
from src.processing.stealer_plugins.base import StealerParserPlugin
import logging

logger = logging.getLogger(__name__)

class LummaParser(StealerParserPlugin):
    """Parser for Lumma/LummaC2 stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "lumma_parser"
        self.value_multiplier = 1.5  # Lumma data is high value due to cookie regeneration
        
        # Lumma specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"Lumma(C2)?[\s]*Stealer|Lumma(C2)?[\s]*Report|Lumma[\s]*Logs", re.IGNORECASE),
            "section_browser": re.compile(r"--+[\s]*(?:Browser[s]?|Browsers Data|Web Data)[\s]*--+", re.IGNORECASE),
            "section_system": re.compile(r"--+[\s]*(?:System Info|System Information|Machine Info)[\s]*--+", re.IGNORECASE),
            "section_crypto": re.compile(r"--+[\s]*(?:Crypto|Wallets|Cryptocurrency|Crypto Wallets)[\s]*--+", re.IGNORECASE),
            "section_files": re.compile(r"--+[\s]*(?:Files|Grabbed Files|Stolen Files)[\s]*--+", re.IGNORECASE),
            
            # Credential formats specific to Lumma
            "credentials": [
                # Domain/Username/Password format
                re.compile(r"Domain:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # URL/Username/Password format
                re.compile(r"URL:[\s]*(https?://[^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Origin/Username/Password format (common in Lumma)
                re.compile(r"Origin:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Hostname/Username/Password format
                re.compile(r"Host(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # System info formats
            "system_info": [
                # OS and version (with Windows edition)
                re.compile(r"OS:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Computer name
                re.compile(r"Computer[\s]*Name:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Username
                re.compile(r"User(?:name)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Hardware ID
                re.compile(r"HWID:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Product ID
                re.compile(r"Product[\s]*ID:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Local IP
                re.compile(r"Local[\s]*IP:[\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
                # Public IP
                re.compile(r"(?:Public[\s]*)?IP(?:\s*Address)?:[\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
                # Country/Location
                re.compile(r"Country:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Language
                re.compile(r"Language:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Anti-virus
                re.compile(r"Antivirus:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                # Wallet with path
                re.compile(r"Wallet:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Bitcoin wallet
                re.compile(r"Bitcoin:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Ethereum wallet
                re.compile(r"Ethereum:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Electrum wallet
                re.compile(r"Electrum:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Atomic wallet
                re.compile(r"Atomic:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Wallet seed phrases
                re.compile(r"Seed[\s]*Phrase:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Private keys (often Base64 encoded in Lumma)
                re.compile(r"Private[\s]*Key:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Metamask (special handling in Lumma)
                re.compile(r"MetaMask:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Exodus wallet
                re.compile(r"Exodus:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Cookie patterns with special handling for regeneration capabilities
            "cookies": [
                # Domain and cookie with expiry (common in Lumma)
                re.compile(r"Domain:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)(?:[\s\r\n]+Expires:[\s]*([^\r\n]+))?", re.IGNORECASE),
                # Host and cookie with expiry
                re.compile(r"Host:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)(?:[\s\r\n]+Expires:[\s]*([^\r\n]+))?", re.IGNORECASE),
                # Service and cookie (often used for API services)
                re.compile(r"Service:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # 2FA/MFA backup codes (Lumma specifically targets these)
            "mfa_codes": re.compile(r"2FA[\s]*Backup[\s]*Codes:[\s]*([^\r\n]+)", re.IGNORECASE),
            
            # File path patterns commonly seen in Lumma
            "file_paths": re.compile(r"(?:File|Path|Document):[\s]*([^\r\n]+\.(?:txt|log|json|dat|wallet|key))", re.IGNORECASE),
            
            # Session token patterns (Lumma specifically targets these for regeneration)
            "session_tokens": re.compile(r"Session[\s]*Token:[\s]*([^\r\n]+)", re.IGNORECASE),
            
            # Base64 data blocks (Lumma often uses these for encoded data)
            "base64_blocks": re.compile(r"(?:Data|B64|Base64):[\s]*([A-Za-z0-9+/=]{20,})", re.IGNORECASE)
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
            
        # Quick check for Lumma headers (high confidence)
        if self._patterns["header"].search(text):
            return True, 0.95
            
        # Check for Lumma's distinctive section markers (medium confidence)
        section_score = 0.0
        if self._patterns["section_browser"].search(text):
            section_score += 0.2
        if self._patterns["section_system"].search(text):
            section_score += 0.2
        if self._patterns["section_crypto"].search(text):
            section_score += 0.2
        if self._patterns["section_files"].search(text):
            section_score += 0.2
            
        # Check for unique Lumma patterns (high confidence)
        if self._patterns["mfa_codes"].search(text):
            section_score += 0.3
        if self._patterns["session_tokens"].search(text):
            section_score += 0.3
            
        # File name check for common Lumma naming
        if message_data.get("media_path"):
            file_name = os.path.basename(message_data["media_path"])
            if re.search(r"(lumma|lummac2)", file_name, re.IGNORECASE):
                section_score += 0.3
                
        # If we have a reasonable confidence, return true
        return section_score >= self.confidence_threshold, section_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Lumma stealer format message.
        
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
            "two_factor_codes": [],  # Specific to Lumma's 2FA targeting
            "session_tokens": [],    # Specific to Lumma's session regeneration capabilities
            "parsing_errors": []
        }
        
        text = message_data.get("text", "")
        if not text:
            return result
            
        # Extract credentials
        for pattern in self._patterns["credentials"]:
            for match in pattern.finditer(text):
                domain_or_url, username, password = match.groups()
                
                # Extract domain from URL or use directly
                domain = None
                url = None
                
                if domain_or_url.startswith(('http://', 'https://')):
                    url = domain_or_url
                    domain = self.extract_domain_from_url(domain_or_url)
                else:
                    domain = domain_or_url
                    
                result["credentials"].append({
                    "url": url,
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
                elif pattern.pattern.startswith("Computer"):
                    system_info["computer_name"] = match.group(1).strip()
                elif pattern.pattern.startswith("User"):
                    system_info["username"] = match.group(1).strip()
                elif pattern.pattern.startswith("HWID:"):
                    system_info["hardware_id"] = match.group(1).strip()
                elif pattern.pattern.startswith("Product"):
                    system_info["product_id"] = match.group(1).strip()
                elif pattern.pattern.startswith("Local"):
                    system_info["local_ip"] = match.group(1).strip()
                elif pattern.pattern.startswith("(?:Public"):
                    system_info["public_ip"] = match.group(1).strip()
                elif pattern.pattern.startswith("Country:"):
                    system_info["country"] = match.group(1).strip()
                elif pattern.pattern.startswith("Language:"):
                    system_info["language"] = match.group(1).strip()
                elif pattern.pattern.startswith("Antivirus:"):
                    system_info["antivirus"] = match.group(1).strip()
                    
        # Check if it's likely a corporate machine
        if system_info:
            # Check for enterprise OS
            if system_info.get("os") and ("enterprise" in system_info["os"].lower() or "business" in system_info["os"].lower()):
                system_info["is_corporate"] = True
                
            # Check for corp naming patterns
            if system_info.get("computer_name"):
                cn = system_info["computer_name"].lower()
                if any(term in cn for term in ["corp", "ent", "wrk", "work", "biz", "company"]):
                    system_info["is_corporate"] = True
                    
            result["system_info"] = system_info
            
        # Extract cookies
        for pattern in self._patterns["cookies"]:
            for match in pattern.finditer(text):
                if len(match.groups()) == 2:
                    domain, cookie_value = match.groups()
                    result["cookies"].append({
                        "domain": domain.strip(),
                        "value": cookie_value.strip(),
                        "can_regenerate": True  # Lumma specifically enables cookie regeneration
                    })
                elif len(match.groups()) == 3:
                    domain, cookie_value, expires = match.groups()
                    result["cookies"].append({
                        "domain": domain.strip(),
                        "value": cookie_value.strip(),
                        "expires": expires.strip() if expires else None,
                        "can_regenerate": True  # Lumma specifically enables cookie regeneration
                    })
                    
        # Extract crypto wallet information
        for pattern in self._patterns["crypto_wallets"]:
            for match in pattern.finditer(text):
                wallet_data = match.group(1).strip()
                wallet_type = "unknown"
                
                # Determine wallet type from pattern
                if "bitcoin" in pattern.pattern.lower():
                    wallet_type = "bitcoin"
                elif "ethereum" in pattern.pattern.lower():
                    wallet_type = "ethereum"
                elif "electrum" in pattern.pattern.lower():
                    wallet_type = "electrum"
                elif "atomic" in pattern.pattern.lower():
                    wallet_type = "atomic"
                elif "metamask" in pattern.pattern.lower():
                    wallet_type = "metamask"
                elif "exodus" in pattern.pattern.lower():
                    wallet_type = "exodus"
                    
                # Special handling for seed phrases and private keys
                if "seed" in pattern.pattern.lower():
                    result["crypto_wallets"].append({
                        "type": wallet_type,
                        "seed_phrase": wallet_data
                    })
                elif "private" in pattern.pattern.lower():
                    # Try to decode if it looks like Base64
                    if re.match(r'^[A-Za-z0-9+/=]+$', wallet_data):
                        try:
                            decoded = self.decode_base64(wallet_data)
                            if decoded != wallet_data:  # If decoding changed the data
                                result["crypto_wallets"].append({
                                    "type": wallet_type,
                                    "private_key": decoded,
                                    "encoded_key": wallet_data
                                })
                            else:
                                result["crypto_wallets"].append({
                                    "type": wallet_type,
                                    "private_key": wallet_data
                                })
                        except binascii.Error:
                            # Expected error if base64 decoding fails
                            result["crypto_wallets"].append({
                                "type": wallet_type,
                                "private_key": wallet_data # Store original if decode fails
                            })
                        except Exception as e:
                             # Log other unexpected errors during decoding
                             logger.warning(f"Unexpected error decoding wallet data in Lumma parser: {e}")
                             result["crypto_wallets"].append({
                                "type": wallet_type,
                                "private_key": wallet_data # Store original
                            })
                    else:
                        result["crypto_wallets"].append({
                            "type": wallet_type,
                            "private_key": wallet_data
                        })
                else:
                    result["crypto_wallets"].append({
                        "type": wallet_type,
                        "path": wallet_data
                    })
                    
                # Add to file paths if it looks like a path
                if os.path.sep in wallet_data or wallet_data.endswith(('.dat', '.wallet')):
                    result["file_paths"].append(wallet_data)
                    
        # Extract 2FA/MFA backup codes (a Lumma specialty)
        for match in self._patterns["mfa_codes"].finditer(text):
            result["two_factor_codes"].append({
                "codes": match.group(1).strip()
            })
            
        # Extract session tokens (for regeneration)
        for match in self._patterns["session_tokens"].finditer(text):
            result["session_tokens"].append({
                "token": match.group(1).strip()
            })
            
        # Extract file paths
        for match in self._patterns["file_paths"].finditer(text):
            path = match.group(1).strip()
            if path not in result["file_paths"]:
                result["file_paths"].append(path)
                
        # Look for Base64 encoded blocks that might contain valuable data
        for match in self._patterns["base64_blocks"].finditer(text):
            encoded_data = match.group(1).strip()
            try:
                decoded = self.decode_base64(encoded_data)
                # If it decodes to something that looks like JSON, try to parse it
                if decoded.strip().startswith('{') and decoded.strip().endswith('}'):
                    try:
                        json_data = json.loads(decoded)
                        # Check if it contains wallet data
                        if any(key in json_data for key in ["wallet", "key", "seed", "mnemonic", "private"]):
                            for key, value in json_data.items():
                                if "private" in key.lower():
                                    result["crypto_wallets"].append({
                                        "type": "unknown",
                                        "private_key": value
                                    })
                                elif "seed" in key.lower() or "mnemonic" in key.lower():
                                    result["crypto_wallets"].append({
                                        "type": "unknown",
                                        "seed_phrase": value
                                    })
                    except json.JSONDecodeError:
                        # Expected if the decoded string is not valid JSON
                        pass 
                    except Exception as e:
                         # Log other unexpected errors during JSON parsing or processing
                         logger.warning(f"Unexpected error processing potential JSON in decoded base64 block (Lumma): {e}")
                         pass # Ignore if we can't process the JSON block
            except binascii.Error:
                # Expected error if base64 decoding fails
                pass
            except Exception as e:
                 # Log other unexpected errors during base64 decoding
                 logger.warning(f"Unexpected error decoding base64 block in Lumma parser: {e}")
                 pass # Ignore if decoding fails unexpectedly
                
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "two_factor_codes", "session_tokens"]:
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
        
        # Add bonus to value score for Lumma's cookie regeneration and 2FA data
        if result["cookies"] or result["two_factor_codes"] or result["session_tokens"]:
            result["value_score"] = min(100, result["value_score"] * 1.2)  # 20% bonus capped at 100
            
        return result
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a Lumma stealer file.
        
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
            "two_factor_codes": [],
            "session_tokens": [],
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
                    
                # Look for Lumma JSON structure
                if isinstance(data, dict):
                    # Extract credentials
                    if "credentials" in data and isinstance(data["credentials"], list):
                        for cred in data["credentials"]:
                            if isinstance(cred, dict):
                                url = cred.get("URL") or cred.get("url")
                                username = cred.get("Username") or cred.get("username")
                                password = cred.get("Password") or cred.get("password")
                                domain = cred.get("Domain") or cred.get("domain")
                                
                                if username and password:
                                    if not domain and url:
                                        domain = self.extract_domain_from_url(url)
                                    elif not domain:
                                        domain = self.extract_domain_from_username(username)
                                        
                                    result["credentials"].append({
                                        "url": url,
                                        "domain": domain,
                                        "username": username,
                                        "password": password
                                    })
                                    
                    # Extract cookies (Lumma specific format with regeneration data)
                    if "cookies" in data and isinstance(data["cookies"], list):
                        for cookie in data["cookies"]:
                            if isinstance(cookie, dict):
                                domain = cookie.get("Domain") or cookie.get("domain") or cookie.get("Host") or cookie.get("host")
                                value = cookie.get("Value") or cookie.get("value") or cookie.get("Cookie") or cookie.get("cookie")
                                expires = cookie.get("Expires") or cookie.get("expires") or cookie.get("ExpiresUtc") or cookie.get("expiresUtc")
                                
                                if domain and value:
                                    cookie_data = {
                                        "domain": domain,
                                        "value": value,
                                        "can_regenerate": True  # Lumma specialty
                                    }
                                    
                                    if expires:
                                        cookie_data["expires"] = expires
                                        
                                    result["cookies"].append(cookie_data)
                                    
                    # Extract Lumma's 2FA/MFA data
                    if "twoFactor" in data or "2fa" in data or "mfa" in data:
                        two_factor = data.get("twoFactor") or data.get("2fa") or data.get("mfa")
                        if isinstance(two_factor, list):
                            for code_set in two_factor:
                                if isinstance(code_set, dict):
                                    service = code_set.get("Service") or code_set.get("service")
                                    codes = code_set.get("Codes") or code_set.get("codes")
                                    if codes:
                                        result["two_factor_codes"].append({
                                            "service": service,
                                            "codes": codes
                                        })
                                elif isinstance(code_set, str):
                                    result["two_factor_codes"].append({
                                        "codes": code_set
                                    })
                                    
                    # Extract session tokens
                    if "sessions" in data or "tokens" in data:
                        sessions = data.get("sessions") or data.get("tokens")
                        if isinstance(sessions, list):
                            for session in sessions:
                                if isinstance(session, dict):
                                    token = session.get("Token") or session.get("token")
                                    service = session.get("Service") or session.get("service")
                                    if token:
                                        result["session_tokens"].append({
                                            "service": service,
                                            "token": token
                                        })
                                elif isinstance(session, str):
                                    result["session_tokens"].append({
                                        "token": session
                                    })
                                    
                    # Extract system info
                    if "system" in data or "systemInfo" in data:
                        system = data.get("system") or data.get("systemInfo")
                        if isinstance(system, dict):
                            sys_info = {}
                            
                            # Map common Lumma system info fields
                            mapping = {
                                "OS": "os", 
                                "os": "os",
                                "ComputerName": "computer_name",
                                "computerName": "computer_name",
                                "UserName": "username",
                                "userName": "username",
                                "HWID": "hardware_id",
                                "hwid": "hardware_id",
                                "ProductID": "product_id",
                                "productId": "product_id",
                                "IP": "public_ip",
                                "ip": "public_ip",
                                "LocalIP": "local_ip",
                                "localIP": "local_ip",
                                "Country": "country",
                                "country": "country",
                                "Language": "language",
                                "language": "language",
                                "Antivirus": "antivirus",
                                "antivirus": "antivirus"
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
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "two_factor_codes", "session_tokens", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result
