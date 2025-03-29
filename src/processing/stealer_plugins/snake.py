"""
SnakeStealer parser plugin.

This module implements a parser for the newer SnakeStealer format.
SnakeStealer is a .NET-based stealer with advanced anti-VM capabilities.
"""

import re
import json
import os
from typing import Dict, Any, Tuple
from src.processing.stealer_plugins.base import StealerParserPlugin
import logging
import binascii

logger = logging.getLogger(__name__)

class SnakeStealerParser(StealerParserPlugin):
    """Parser for SnakeStealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "snake_stealer_parser"
        self.value_multiplier = 1.4  # SnakeStealer targets SSO tokens for enterprise systems
        
        # SnakeStealer specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"Snake[\s]*Stealer|Snake[\s]*Report|Snake[\s]*Logs|SnakeLog", re.IGNORECASE),
            "json_format": re.compile(r"^\s*\{\s*\"", re.MULTILINE),  # SnakeStealer often uses serialized JSON
            "section_browser": re.compile(r"<<[\s]*(?:Browser|Browsers|Web)[\s]*>>", re.IGNORECASE),
            "section_system": re.compile(r"<<[\s]*(?:System|System Info|Machine|PC Info)[\s]*>>", re.IGNORECASE),
            "section_crypto": re.compile(r"<<[\s]*(?:Crypto|Wallets|Cryptocurrency)[\s]*>>", re.IGNORECASE),
            "section_sso": re.compile(r"<<[\s]*(?:SSO|Single Sign-On|Enterprise Tokens)[\s]*>>", re.IGNORECASE),
            
            # Credential formats specific to SnakeStealer (more JSON-oriented)
            "credentials": [
                # URL/Username/Password format
                re.compile(r"\"url\":\s*\"(https?://[^\"]+)\"[^}]+\"username\":\s*\"([^\"]+)\"[^}]+\"password\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Domain/Username/Password format
                re.compile(r"\"domain\":\s*\"([^\"]+)\"[^}]+\"username\":\s*\"([^\"]+)\"[^}]+\"password\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Fallback to text-based format
                re.compile(r"URL:[\s]*(https?://[^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                re.compile(r"Domain:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # System info formats
            "system_info": [
                # OS version
                re.compile(r"\"os\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Hardware ID
                re.compile(r"\"hwid\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Computer name
                re.compile(r"\"computerName\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Username
                re.compile(r"\"username\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # IP address
                re.compile(r"\"ip\":\s*\"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\"", re.IGNORECASE),
                # Country
                re.compile(r"\"country\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Installed software (unique to SnakeStealer)
                re.compile(r"\"installedSoftware\":\s*(\[.+?\])", re.IGNORECASE | re.DOTALL),
                # Anti-VM detection (unique to SnakeStealer)
                re.compile(r"\"isVirtualMachine\":\s*(true|false)", re.IGNORECASE),
                # Domain joined status (enterprise targeting)
                re.compile(r"\"isDomainJoined\":\s*(true|false)", re.IGNORECASE)
            ],
            
            # SnakeStealer's base64 embedded data blocks
            "base64_blocks": re.compile(r"\"data\":\s*\"([A-Za-z0-9+/=]{20,})\"", re.IGNORECASE),
            
            # SSO token patterns (SnakeStealer specialty)
            "sso_tokens": [
                re.compile(r"\"tokenType\":\s*\"([^\"]+)\"[^}]+\"tokenValue\":\s*\"([^\"]+)\"", re.IGNORECASE),
                re.compile(r"\"ssoProvider\":\s*\"([^\"]+)\"[^}]+\"token\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Fallback text pattern
                re.compile(r"Provider:[\s]*([^\s\r\n]+)[\s\r\n]+Token:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # Cookie patterns in SnakeStealer format
            "cookies": [
                # JSON format
                re.compile(r"\"domain\":\s*\"([^\"]+)\"[^}]+\"cookie\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Text format
                re.compile(r"Domain:[\s]*([^\s\r\n]+)[\s\r\n]+Cookie:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                # JSON format
                re.compile(r"\"walletType\":\s*\"([^\"]+)\"[^}]+\"(?:data|path)\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Private key format
                re.compile(r"\"walletType\":\s*\"([^\"]+)\"[^}]+\"privateKey\":\s*\"([^\"]+)\"", re.IGNORECASE),
                # Text format
                re.compile(r"Wallet Type:[\s]*([^\s\r\n]+)[\s\r\n]+(?:Data|Path):[\s]*([^\s\r\n]+)", re.IGNORECASE)
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
            
        # Quick check for SnakeStealer headers (high confidence)
        if self._patterns["header"].search(text):
            return True, 0.95
            
        # SnakeStealer often uses JSON serialized format
        if self._patterns["json_format"].search(text):
            # Look for specific SnakeStealer JSON patterns
            if any(pattern.search(text) for pattern in self._patterns["sso_tokens"]):
                # SSO tokens are a SnakeStealer specialty
                return True, 0.85
                
        # Check for SnakeStealer's distinctive section markers (medium confidence)
        section_score = 0.0
        if self._patterns["section_browser"].search(text):
            section_score += 0.15
        if self._patterns["section_system"].search(text):
            section_score += 0.15
        if self._patterns["section_crypto"].search(text):
            section_score += 0.15
        if self._patterns["section_sso"].search(text):
            section_score += 0.35  # Higher weight for SnakeStealer's specialty
            
        # Check for Base64 data blocks (common in SnakeStealer)
        if self._patterns["base64_blocks"].search(text):
            section_score += 0.2
            
        # File name check for common SnakeStealer naming
        if message_data.get("media_path"):
            file_name = os.path.basename(message_data["media_path"])
            if re.search(r"(snake_?stealer|snake_?log)", file_name, re.IGNORECASE):
                section_score += 0.3
                
        # If we have a reasonable confidence, return true
        return section_score >= self.confidence_threshold, section_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse SnakeStealer format message.
        
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
            "sso_tokens": [],  # SnakeStealer specialty
            "parsing_errors": []
        }
        
        text = message_data.get("text", "")
        if not text:
            return result
            
        # Try to parse as JSON first if it looks like JSON
        if self._patterns["json_format"].search(text):
            try:
                # Find the start of the JSON object
                json_start = re.search(r"^\s*\{", text, re.MULTILINE)
                if json_start:
                    # Extract the JSON part
                    json_text = text[json_start.start():]
                    # Try to find the end of the JSON object
                    brace_count = 0
                    for i, c in enumerate(json_text):
                        if c == '{':
                            brace_count += 1
                        elif c == '}':
                            brace_count -= 1
                            if brace_count == 0:
                                json_text = json_text[:i+1]
                                break
                                
                    try:
                        data = json.loads(json_text)
                        return self._parse_json(data)
                    except json.JSONDecodeError:
                        # Failed to parse as JSON, continue with regex
                        pass
                    except Exception as e:
                         # Log other unexpected errors during JSON parsing
                         logger.warning(f"Unexpected error parsing initial JSON block in Snake parser: {e}")
                         pass # Fallback to regex
            except Exception as e:
                # Catch errors during the initial JSON search/extraction logic
                logger.warning(f"Error during initial JSON block search/extraction in Snake parser: {e}")
                pass # Fallback to regex extraction
                
        # Extract credentials using regex
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
                    "username": username.replace('\\"', '"'),  # Unescape JSON strings
                    "password": password.replace('\\"', '"')   # Unescape JSON strings
                })
                
        # Extract system information
        system_info = {}
        for pattern in self._patterns["system_info"]:
            match = pattern.search(text)
            if match:
                if "os" in pattern.pattern:
                    system_info["os"] = match.group(1).replace('\\"', '"')
                elif "hwid" in pattern.pattern:
                    system_info["hardware_id"] = match.group(1).replace('\\"', '"')
                elif "computerName" in pattern.pattern:
                    system_info["computer_name"] = match.group(1).replace('\\"', '"')
                elif "username" in pattern.pattern:
                    system_info["username"] = match.group(1).replace('\\"', '"')
                elif "ip" in pattern.pattern:
                    system_info["public_ip"] = match.group(1)
                elif "country" in pattern.pattern:
                    system_info["country"] = match.group(1).replace('\\"', '"')
                elif "installedSoftware" in pattern.pattern:
                    try:
                        software_json = match.group(1)
                        system_info["installed_software"] = software_json
                    except IndexError:
                         # Expected if regex group doesn't exist
                         pass
                    except Exception as e:
                         # Log unexpected errors getting the regex group
                         logger.warning(f"Unexpected error getting software_json regex group in Snake parser: {e}")
                         pass # Ignore if we can't get this specific info
                elif "isVirtualMachine" in pattern.pattern:
                    system_info["is_virtual_machine"] = match.group(1).lower() == "true"
                elif "isDomainJoined" in pattern.pattern:
                    system_info["is_domain_joined"] = match.group(1).lower() == "true"
                    # Enterprise marker
                    if match.group(1).lower() == "true":
                        system_info["is_corporate"] = True
                    
        if system_info:
            result["system_info"] = system_info
            
        # Extract SSO tokens (specialty of SnakeStealer)
        for pattern in self._patterns["sso_tokens"]:
            for match in pattern.finditer(text):
                provider, token = match.groups()
                result["sso_tokens"].append({
                    "provider": provider.replace('\\"', '"'),
                    "token": token.replace('\\"', '"')
                })
                
        # Extract cookies
        for pattern in self._patterns["cookies"]:
            for match in pattern.finditer(text):
                domain, cookie_value = match.groups()
                result["cookies"].append({
                    "domain": domain.replace('\\"', '"'),
                    "value": cookie_value.replace('\\"', '"')
                })
                
        # Extract crypto wallet information
        for pattern in self._patterns["crypto_wallets"]:
            for match in pattern.finditer(text):
                wallet_type, wallet_data = match.groups()
                
                if "privateKey" in pattern.pattern:
                    result["crypto_wallets"].append({
                        "type": wallet_type.replace('\\"', '"').lower(),
                        "private_key": wallet_data.replace('\\"', '"')
                    })
                else:
                    result["crypto_wallets"].append({
                        "type": wallet_type.replace('\\"', '"').lower(),
                        "path": wallet_data.replace('\\"', '"')
                    })
                    
                    # Add to file paths if it looks like a path
                    if os.path.sep in wallet_data or wallet_data.endswith(('.dat', '.wallet')):
                        result["file_paths"].append(wallet_data.replace('\\"', '"'))
                    
        # Extract Base64 encoded data blocks (common in SnakeStealer)
        for match in self._patterns["base64_blocks"].finditer(text):
            encoded_data = match.group(1)
            try:
                decoded = self.decode_base64(encoded_data)
                # Check if the decoded data looks like JSON
                if decoded.strip().startswith('{') and decoded.strip().endswith('}'):
                    try:
                        json_data = json.loads(decoded)
                        # Process the embedded JSON data
                        embedded_result = self._parse_json(json_data)
                        
                        # Merge results
                        for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "sso_tokens"]:
                            if key in embedded_result and embedded_result[key]:
                                result[key].extend(embedded_result[key])
                                
                        # Merge system info (dictionary)
                        if embedded_result.get("system_info"):
                            result["system_info"].update(embedded_result["system_info"])
                    except json.JSONDecodeError:
                        # Expected if the decoded string is not valid JSON
                        pass
                    except Exception as e:
                        # Log other unexpected errors during embedded JSON parsing
                        logger.warning(f"Unexpected error processing embedded JSON in decoded base64 block (Snake): {e}")
                        pass # Ignore if we can't process the embedded JSON
            except binascii.Error:
                # Expected error if base64 decoding fails
                pass
            except Exception as e:
                # Log other unexpected errors during base64 decoding
                logger.warning(f"Unexpected error decoding base64 block in Snake parser: {e}")
                pass # Ignore if decoding fails unexpectedly
                
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "sso_tokens"]:
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
        
        # Add bonus to value score for SSO tokens which are high value
        if result["sso_tokens"]:
            result["value_score"] = min(100, result["value_score"] * 1.3)  # 30% bonus capped at 100
            
        # Add bonus for corporate machines
        if result["system_info"].get("is_corporate") or result["system_info"].get("is_domain_joined"):
            result["value_score"] = min(100, result["value_score"] * 1.2)  # 20% bonus capped at 100
            
        return result
        
    def _parse_json(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse SnakeStealer JSON format.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            Dictionary with extracted structured data
        """
        result = {
            "credentials": [],
            "cookies": [],
            "system_info": {},
            "crypto_wallets": [],
            "file_paths": [],
            "sso_tokens": [],
            "parsing_errors": []
        }
        
        # Extract credentials
        if "credentials" in data and isinstance(data["credentials"], list):
            for cred in data["credentials"]:
                if isinstance(cred, dict):
                    url = cred.get("url") or cred.get("URL")
                    domain = cred.get("domain") or cred.get("Domain")
                    username = cred.get("username") or cred.get("Username")
                    password = cred.get("password") or cred.get("Password")
                    
                    if username and password:
                        if not domain and url:
                            domain = self.extract_domain_from_url(url)
                        elif not domain and username and '@' in username:
                            domain = self.extract_domain_from_username(username)
                            
                        result["credentials"].append({
                            "url": url,
                            "domain": domain,
                            "username": username,
                            "password": password
                        })
                        
        # Extract system info
        if "systemInfo" in data and isinstance(data["systemInfo"], dict):
            system_info = {}
            system = data["systemInfo"]
            
            # Map SnakeStealer system info fields
            mapping = {
                "os": "os",
                "OS": "os",
                "computerName": "computer_name",
                "ComputerName": "computer_name",
                "userName": "username",
                "UserName": "username",
                "username": "username",
                "hwid": "hardware_id",
                "HWID": "hardware_id",
                "hardwareId": "hardware_id",
                "ip": "public_ip",
                "IP": "public_ip",
                "publicIP": "public_ip",
                "country": "country",
                "Country": "country",
                "isVirtualMachine": "is_virtual_machine",
                "IsVirtualMachine": "is_virtual_machine",
                "isDomainJoined": "is_domain_joined",
                "IsDomainJoined": "is_domain_joined"
            }
            
            for src, dest in mapping.items():
                if src in system:
                    if isinstance(system[src], bool):
                        system_info[dest] = system[src]
                    elif isinstance(system[src], str):
                        system_info[dest] = system[src]
                    elif system[src] is not None:
                        system_info[dest] = str(system[src])
                        
            # Check for installed software
            if "installedSoftware" in system and isinstance(system["installedSoftware"], list):
                system_info["installed_software"] = system["installedSoftware"]
                
                # Check for enterprise software indicators
                enterprise_software = ["citrix", "vpn", "symantec", "mcafee", "enterprise", "sql server", 
                                       "oracle", "sap", "jira", "confluence", "salesforce", "workday"]
                                       
                for software in system["installedSoftware"]:
                    if isinstance(software, str) and any(e in software.lower() for e in enterprise_software):
                        system_info["is_corporate"] = True
                        break
                        
            # Mark domain-joined machines as corporate
            if system.get("isDomainJoined") or system.get("IsDomainJoined"):
                system_info["is_corporate"] = True
                
            if system_info:
                result["system_info"] = system_info
                
        # Extract SSO tokens
        if "ssoTokens" in data and isinstance(data["ssoTokens"], list):
            for token in data["ssoTokens"]:
                if isinstance(token, dict):
                    provider = token.get("provider") or token.get("Provider") or token.get("tokenType") or token.get("TokenType")
                    value = token.get("token") or token.get("Token") or token.get("tokenValue") or token.get("TokenValue")
                    
                    if provider and value:
                        result["sso_tokens"].append({
                            "provider": provider,
                            "token": value
                        })
                        
        # Extract cookies
        if "cookies" in data and isinstance(data["cookies"], list):
            for cookie in data["cookies"]:
                if isinstance(cookie, dict):
                    domain = cookie.get("domain") or cookie.get("Domain") or cookie.get("host") or cookie.get("Host")
                    value = cookie.get("value") or cookie.get("Value") or cookie.get("cookie") or cookie.get("Cookie")
                    
                    if domain and value:
                        result["cookies"].append({
                            "domain": domain,
                            "value": value
                        })
                        
        # Extract crypto wallets
        if "wallets" in data and isinstance(data["wallets"], list):
            for wallet in data["wallets"]:
                if isinstance(wallet, dict):
                    wallet_type = wallet.get("type") or wallet.get("Type") or wallet.get("walletType") or wallet.get("WalletType")
                    
                    # Check for private keys
                    if "privateKey" in wallet or "PrivateKey" in wallet:
                        private_key = wallet.get("privateKey") or wallet.get("PrivateKey")
                        if wallet_type and private_key:
                            result["crypto_wallets"].append({
                                "type": wallet_type.lower(),
                                "private_key": private_key
                            })
                    # Check for seed phrases        
                    elif "seedPhrase" in wallet or "SeedPhrase" in wallet or "mnemonic" in wallet or "Mnemonic" in wallet:
                        seed = wallet.get("seedPhrase") or wallet.get("SeedPhrase") or wallet.get("mnemonic") or wallet.get("Mnemonic")
                        if wallet_type and seed:
                            result["crypto_wallets"].append({
                                "type": wallet_type.lower(),
                                "seed_phrase": seed
                            })
                    # Check for paths
                    elif "path" in wallet or "Path" in wallet or "data" in wallet or "Data" in wallet:
                        path = wallet.get("path") or wallet.get("Path") or wallet.get("data") or wallet.get("Data")
                        if wallet_type and path:
                            result["crypto_wallets"].append({
                                "type": wallet_type.lower(),
                                "path": path
                            })
                            
                            # Add to file paths if it looks like a path
                            if os.path.sep in path or path.endswith(('.dat', '.wallet')):
                                result["file_paths"].append(path)
                                
        return result
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a SnakeStealer file.
        
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
            "sso_tokens": [],
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
                    
                # Process JSON data
                json_result = self._parse_json(data)
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "sso_tokens"]:
                    if key in json_result and json_result[key]:
                        result[key].extend(json_result[key])
                        
                # Merge system info (dictionary)
                if json_result.get("system_info"):
                    result["system_info"].update(json_result["system_info"])
                    
            elif ext in ['.txt', '.log']:
                # Process as plain text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Use the same parsing logic as for message text
                text_result = self.parse({"text": text})
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", "sso_tokens", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result
