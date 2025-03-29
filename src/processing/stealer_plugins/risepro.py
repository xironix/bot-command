"""
RisePro Stealer parser plugin.

This module implements a parser for the RisePro stealer format.
RisePro had significant growth in 2024 before being shut down in June 2024.
"""

import re
import json
import os
from typing import Dict, List, Any, Tuple, Optional
from src.processing.stealer_plugins.base import StealerParserPlugin

class RiseProParser(StealerParserPlugin):
    """Parser for RisePro stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "risepro_parser"
        self.value_multiplier = 1.3  # RisePro has high quality credential collection
        
        # RisePro specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"Rise[\s]*Pro|RisePro[\s]*Stealer|RisePro[\s]*Log|RisePro[\s]*Report", re.IGNORECASE),
            "section_browser": re.compile(r"[\*=]{2,}[\s]*(?:Browser|Passwords|Autofill|Cards)[\s]*[\*=]{2,}", re.IGNORECASE),
            "section_system": re.compile(r"[\*=]{2,}[\s]*(?:System|Hardware|PC Info)[\s]*[\*=]{2,}", re.IGNORECASE),
            "section_crypto": re.compile(r"[\*=]{2,}[\s]*(?:Crypto|Wallet|Wallets)[\s]*[\*=]{2,}", re.IGNORECASE),
            "section_ftp": re.compile(r"[\*=]{2,}[\s]*(?:FTP|FileZilla)[\s]*[\*=]{2,}", re.IGNORECASE),
            "section_vpn": re.compile(r"[\*=]{2,}[\s]*(?:VPN|OpenVPN|NordVPN)[\s]*[\*=]{2,}", re.IGNORECASE),
            
            # Credential formats specific to RisePro
            "credentials": [
                # URL/Username/Password format
                re.compile(r"URL:[\s]*(https?://[^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Host/Username/Password format
                re.compile(r"Host:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Website/Login/Password format
                re.compile(r"Website:[\s]*([^\s\r\n]+)[\s\r\n]+Login:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # FTP format
                re.compile(r"FTP Host:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # VPN format
                re.compile(r"VPN Host:[\s]*([^\s\r\n]+)[\s\r\n]+Username:[\s]*([^\s\r\n]+)[\s\r\n]+Password:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # Credit card formats specific to RisePro
            "credit_cards": [
                re.compile(r"Card Number:[\s]*(\d{13,19})[\s\r\n]+Expiry:[\s]*(\d{2}/\d{2,4})[\s\r\n]+CVV:[\s]*(\d{3,4})[\s\r\n]+(?:Name:[\s]*([^\r\n]+))?", re.IGNORECASE),
                re.compile(r"Number:[\s]*(\d{13,19})[\s\r\n]+Exp:[\s]*(\d{2}/\d{2,4})[\s\r\n]+CVC:[\s]*(\d{3,4})[\s\r\n]+(?:Holder:[\s]*([^\r\n]+))?", re.IGNORECASE)
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
                # Country
                re.compile(r"Country:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Language
                re.compile(r"Language:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Antivirus
                re.compile(r"Antivirus:[\s]*([^\r\n]+)", re.IGNORECASE),
                # IP address
                re.compile(r"IP(?:\s*Address)?:[\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
                # Screen resolution
                re.compile(r"Resolution:[\s]*(\d+\s*[xX]\s*\d+)", re.IGNORECASE),
                # CPU
                re.compile(r"CPU:[\s]*([^\r\n]+)", re.IGNORECASE),
                # GPU
                re.compile(r"GPU:[\s]*([^\r\n]+)", re.IGNORECASE),
                # RAM
                re.compile(r"RAM:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Domain joined
                re.compile(r"Domain[\s]*Joined:[\s]*(Yes|No|True|False)", re.IGNORECASE)
            ],
            
            # Cookie patterns
            "cookies": [
                # Domain and cookie format
                re.compile(r"Host:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Domain:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                # Wallet paths
                re.compile(r"Wallet:[\s]*([^\r\n]+\.wallet|[^\r\n]+\.dat)", re.IGNORECASE),
                # Bitcoin wallets
                re.compile(r"Bitcoin:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Ethereum wallets
                re.compile(r"Ethereum:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Specific wallets
                re.compile(r"(?:Atomic|Exodus|Electrum|Jaxx|Binance):[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Telegram sessions (RisePro often targets these)
            "telegram": re.compile(r"Telegram[\s]*(?:Session|Data):[\s]*([^\r\n]+)", re.IGNORECASE),
            
            # Discord tokens (RisePro often targets these)
            "discord": re.compile(r"Discord[\s]*Token:[\s]*([^\r\n]+)", re.IGNORECASE)
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
            
        # Quick check for RisePro headers (high confidence)
        if self._patterns["header"].search(text):
            return True, 0.95
            
        # Check for RisePro's distinctive section markers (medium confidence)
        section_score = 0.0
        if self._patterns["section_browser"].search(text):
            section_score += 0.15
        if self._patterns["section_system"].search(text):
            section_score += 0.15
        if self._patterns["section_crypto"].search(text):
            section_score += 0.15
        if self._patterns["section_ftp"].search(text):
            section_score += 0.2  # More specific to RisePro
        if self._patterns["section_vpn"].search(text):
            section_score += 0.2  # More specific to RisePro
            
        # Check for RisePro's credit card format (high confidence)
        for pattern in self._patterns["credit_cards"]:
            if pattern.search(text):
                section_score += 0.3
                break
                
        # Check for RisePro's telegram/discord patterns (high confidence)
        if self._patterns["telegram"].search(text):
            section_score += 0.25
        if self._patterns["discord"].search(text):
            section_score += 0.25
            
        # File name check for common RisePro naming
        if message_data.get("media_path"):
            file_name = os.path.basename(message_data["media_path"])
            if re.search(r"(rise_?pro|risepro)", file_name, re.IGNORECASE):
                section_score += 0.3
                
        # If we have a reasonable confidence, return true
        return section_score >= self.confidence_threshold, section_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse RisePro stealer format message.
        
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
            "credit_cards": [],     # RisePro specialty
            "messenger_tokens": [], # RisePro specialty (Telegram, Discord)
            "file_paths": [],
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
                    
                # Special handling for VPN and FTP credentials
                credential_type = "web"
                if "FTP Host" in pattern.pattern:
                    credential_type = "ftp"
                elif "VPN Host" in pattern.pattern:
                    credential_type = "vpn"
                    
                result["credentials"].append({
                    "url": url,
                    "domain": domain,
                    "username": username,
                    "password": password,
                    "type": credential_type
                })
                
        # Extract credit cards (RisePro specialty)
        for pattern in self._patterns["credit_cards"]:
            for match in pattern.finditer(text):
                if len(match.groups()) == 3:
                    card_number, expiry, cvv = match.groups()
                    result["credit_cards"].append({
                        "number": card_number,
                        "expiry": expiry,
                        "cvv": cvv
                    })
                elif len(match.groups()) == 4:
                    card_number, expiry, cvv, holder = match.groups()
                    result["credit_cards"].append({
                        "number": card_number,
                        "expiry": expiry,
                        "cvv": cvv,
                        "holder": holder if holder else None
                    })
                    
        # Extract system information
        system_info = {}
        for pattern in self._patterns["system_info"]:
            match = pattern.search(text)
            if match:
                if "OS:" in pattern.pattern:
                    system_info["os"] = match.group(1).strip()
                elif "HWID:" in pattern.pattern:
                    system_info["hardware_id"] = match.group(1).strip()
                elif "Computer Name:" in pattern.pattern:
                    system_info["computer_name"] = match.group(1).strip()
                elif "User(?:name)?:" in pattern.pattern:
                    system_info["username"] = match.group(1).strip()
                elif "Country:" in pattern.pattern:
                    system_info["country"] = match.group(1).strip()
                elif "Language:" in pattern.pattern:
                    system_info["language"] = match.group(1).strip()
                elif "Antivirus:" in pattern.pattern:
                    system_info["antivirus"] = match.group(1).strip()
                elif "IP(?:" in pattern.pattern:
                    system_info["public_ip"] = match.group(1).strip()
                elif "Resolution:" in pattern.pattern:
                    system_info["screen_resolution"] = match.group(1).strip()
                elif "CPU:" in pattern.pattern:
                    system_info["cpu"] = match.group(1).strip()
                elif "GPU:" in pattern.pattern:
                    system_info["gpu"] = match.group(1).strip()
                elif "RAM:" in pattern.pattern:
                    system_info["ram"] = match.group(1).strip()
                elif "Domain" in pattern.pattern:
                    domain_joined = match.group(1).strip().lower()
                    is_domain = domain_joined in ["yes", "true"]
                    system_info["is_domain_joined"] = is_domain
                    if is_domain:
                        system_info["is_corporate"] = True
                    
        # Check for other enterprise indicators
        if "os" in system_info:
            os_lower = system_info["os"].lower()
            if "enterprise" in os_lower or "business" in os_lower or "server" in os_lower:
                system_info["is_corporate"] = True
                
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
                wallet_data = match.group(1).strip()
                wallet_type = "unknown"
                
                # Determine wallet type from pattern
                if "Bitcoin" in pattern.pattern:
                    wallet_type = "bitcoin"
                elif "Ethereum" in pattern.pattern:
                    wallet_type = "ethereum"
                elif "Atomic" in pattern.pattern:
                    wallet_type = "atomic"
                elif "Exodus" in pattern.pattern:
                    wallet_type = "exodus"
                elif "Electrum" in pattern.pattern:
                    wallet_type = "electrum"
                elif "Jaxx" in pattern.pattern:
                    wallet_type = "jaxx"
                elif "Binance" in pattern.pattern:
                    wallet_type = "binance"
                    
                result["crypto_wallets"].append({
                    "type": wallet_type,
                    "path": wallet_data
                })
                
                # Add to file paths if it looks like a path
                if os.path.sep in wallet_data or wallet_data.endswith(('.dat', '.wallet')):
                    result["file_paths"].append(wallet_data)
                    
        # Extract Telegram session data
        for match in self._patterns["telegram"].finditer(text):
            session_data = match.group(1).strip()
            result["messenger_tokens"].append({
                "type": "telegram",
                "path": session_data
            })
            
            # Add to file paths
            if os.path.sep in session_data:
                result["file_paths"].append(session_data)
                
        # Extract Discord tokens
        for match in self._patterns["discord"].finditer(text):
            token = match.group(1).strip()
            result["messenger_tokens"].append({
                "type": "discord",
                "token": token
            })
                
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "credit_cards", "messenger_tokens", "file_paths"]:
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
        
        # Add bonus to value score for credit cards
        if result["credit_cards"]:
            result["value_score"] = min(100, result["value_score"] * 1.2)  # 20% bonus capped at 100
            
        # Add bonus for messenger tokens
        if result["messenger_tokens"]:
            result["value_score"] = min(100, result["value_score"] * 1.1)  # 10% bonus capped at 100
            
        return result
        
    def calculate_value_score(self, parsed_data: Dict[str, Any]) -> float:
        """
        Calculate value score for parsed data with RisePro-specific scoring.
        
        Args:
            parsed_data: Dictionary with parsed data
            
        Returns:
            Value score (0-100)
        """
        # Use the base value calculation
        score = super().calculate_value_score(parsed_data)
        
        # Add value for credit cards (high value)
        for card in parsed_data.get("credit_cards", []):
            # Each credit card is very valuable
            score += 25
            
        # Add value for messenger tokens
        for token in parsed_data.get("messenger_tokens", []):
            if token.get("type") == "telegram":
                score += 15  # Telegram sessions can be used for account takeover
            elif token.get("type") == "discord":
                score += 10  # Discord tokens can be used for account takeover
                
        # Cap at 100
        return min(score, 100)
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a RisePro stealer file.
        
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
            "credit_cards": [],
            "messenger_tokens": [],
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
                    
                # Look for RisePro JSON structure
                if isinstance(data, dict):
                    # Extract credentials
                    if "credentials" in data and isinstance(data["credentials"], list):
                        for cred in data["credentials"]:
                            if isinstance(cred, dict):
                                url = cred.get("URL") or cred.get("url")
                                host = cred.get("Host") or cred.get("host")
                                username = cred.get("Username") or cred.get("username") or cred.get("Login") or cred.get("login")
                                password = cred.get("Password") or cred.get("password")
                                cred_type = cred.get("Type") or cred.get("type") or "web"
                                
                                if username and password:
                                    domain = None
                                    if url:
                                        domain = self.extract_domain_from_url(url)
                                    elif host:
                                        domain = host
                                    elif username and '@' in username:
                                        domain = self.extract_domain_from_username(username)
                                        
                                    result["credentials"].append({
                                        "url": url,
                                        "domain": domain,
                                        "username": username,
                                        "password": password,
                                        "type": cred_type
                                    })
                                    
                    # Extract credit cards
                    if "cards" in data and isinstance(data["cards"], list):
                        for card in data["cards"]:
                            if isinstance(card, dict):
                                number = card.get("Number") or card.get("number") or card.get("CardNumber") or card.get("cardNumber")
                                expiry = card.get("Expiry") or card.get("expiry") or card.get("Exp") or card.get("exp")
                                cvv = card.get("CVV") or card.get("cvv") or card.get("CVC") or card.get("cvc")
                                holder = card.get("Name") or card.get("name") or card.get("Holder") or card.get("holder")
                                
                                if number and (expiry or cvv):
                                    card_data = {
                                        "number": number
                                    }
                                    
                                    if expiry:
                                        card_data["expiry"] = expiry
                                    if cvv:
                                        card_data["cvv"] = cvv
                                    if holder:
                                        card_data["holder"] = holder
                                        
                                    result["credit_cards"].append(card_data)
                                    
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
                        
                        # Map RisePro system info fields
                        mapping = {
                            "OS": "os",
                            "os": "os",
                            "ComputerName": "computer_name",
                            "computerName": "computer_name",
                            "UserName": "username",
                            "userName": "username",
                            "Username": "username",
                            "HWID": "hardware_id",
                            "hwid": "hardware_id",
                            "HardwareID": "hardware_id",
                            "hardwareId": "hardware_id",
                            "IP": "public_ip",
                            "ip": "public_ip",
                            "IPAddress": "public_ip",
                            "ipAddress": "public_ip",
                            "Country": "country",
                            "country": "country",
                            "Language": "language",
                            "language": "language",
                            "Antivirus": "antivirus",
                            "antivirus": "antivirus",
                            "Resolution": "screen_resolution",
                            "resolution": "screen_resolution",
                            "screenResolution": "screen_resolution",
                            "CPU": "cpu",
                            "cpu": "cpu",
                            "GPU": "gpu",
                            "gpu": "gpu",
                            "RAM": "ram",
                            "ram": "ram",
                            "DomainJoined": "is_domain_joined",
                            "domainJoined": "is_domain_joined",
                            "isDomainJoined": "is_domain_joined"
                        }
                        
                        for src, dest in mapping.items():
                            if src in system:
                                if isinstance(system[src], bool):
                                    sys_info[dest] = system[src]
                                elif isinstance(system[src], str):
                                    sys_info[dest] = system[src]
                                elif system[src] is not None:
                                    sys_info[dest] = str(system[src])
                                    
                        # Check for domain joined (enterprise indicator)
                        if "is_domain_joined" in sys_info and sys_info["is_domain_joined"]:
                            sys_info["is_corporate"] = True
                            
                        # Check for enterprise OS
                        if "os" in sys_info:
                            os_lower = sys_info["os"].lower()
                            if "enterprise" in os_lower or "business" in os_lower or "server" in os_lower:
                                sys_info["is_corporate"] = True
                                
                        if sys_info:
                            result["system_info"] = sys_info
                            
                    # Extract crypto wallets
                    if "wallets" in data and isinstance(data["wallets"], list):
                        for wallet in data["wallets"]:
                            if isinstance(wallet, dict):
                                wallet_type = wallet.get("Type") or wallet.get("type") or "unknown"
                                path = wallet.get("Path") or wallet.get("path")
                                
                                if path:
                                    result["crypto_wallets"].append({
                                        "type": wallet_type.lower(),
                                        "path": path
                                    })
                                    
                                    # Add to file paths
                                    if os.path.sep in path or path.endswith(('.dat', '.wallet')):
                                        result["file_paths"].append(path)
                                        
                    # Extract messenger tokens
                    if "messengers" in data and isinstance(data["messengers"], list):
                        for messenger in data["messengers"]:
                            if isinstance(messenger, dict):
                                messenger_type = messenger.get("Type") or messenger.get("type")
                                if messenger_type:
                                    messenger_type = messenger_type.lower()
                                    
                                # Handle Telegram
                                if messenger_type == "telegram":
                                    path = messenger.get("Path") or messenger.get("path")
                                    if path:
                                        result["messenger_tokens"].append({
                                            "type": "telegram",
                                            "path": path
                                        })
                                        
                                        # Add to file paths
                                        if os.path.sep in path:
                                            result["file_paths"].append(path)
                                            
                                # Handle Discord
                                elif messenger_type == "discord":
                                    token = messenger.get("Token") or messenger.get("token")
                                    if token:
                                        result["messenger_tokens"].append({
                                            "type": "discord",
                                            "token": token
                                        })
                                        
            elif ext in ['.txt', '.log']:
                # Process as plain text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Use the same parsing logic as for message text
                text_result = self.parse({"text": text})
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "credit_cards", "messenger_tokens", "file_paths", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result
