"""
Vidar Stealer parser plugin.

This module implements a parser for the Vidar stealer format.
Vidar is a veteran stealer active since 2018, known for targeting financial data.
"""

import re
import json
import os
from typing import Dict, Any, Tuple
from src.processing.stealer_plugins.base import StealerParserPlugin

class VidarParser(StealerParserPlugin):
    """Parser for Vidar stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "vidar_parser"
        self.value_multiplier = 1.25  # Vidar has strong financial credential targeting
        
        # Vidar specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"Vidar[\s]*Stealer|Vidar[\s]*Log|Vidar[\s]*Report|Vidar[\s]*Results", re.IGNORECASE),
            "section_browser": re.compile(r"<\[[\s]*(?:Browsers?|Passwords?|Cookies?|Autofill)[\s]*\]>", re.IGNORECASE),
            "section_system": re.compile(r"<\[[\s]*(?:System|System Info|PC Info|Machine)[\s]*\]>", re.IGNORECASE),
            "section_crypto": re.compile(r"<\[[\s]*(?:Crypto|Wallets?|Cryptocurrency)[\s]*\]>", re.IGNORECASE),
            "section_ftp": re.compile(r"<\[[\s]*(?:FTP|FTP Clients?)[\s]*\]>", re.IGNORECASE),
            "section_messenger": re.compile(r"<\[[\s]*(?:Messenger|Discord|Telegram)[\s]*\]>", re.IGNORECASE),
            
            # Credential formats specific to Vidar
            "credentials": [
                # URL/Username/Password format
                re.compile(r"URL:[\s]*(https?://[^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Host/Username/Password format
                re.compile(r"Host:[\s]*([^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Application/Username/Password format (Vidar often details these)
                re.compile(r"(?:App|Application):[\s]*([^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # FTP format
                re.compile(r"FTP Host:[\s]*([^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # Credit card formats
            "credit_cards": [
                re.compile(r"Card Number:[\s]*(\d{13,19})[\s\r\n]+Exp(?:iry)?:[\s]*(\d{2}/\d{2,4})[\s\r\n]+CVV:[\s]*(\d{3,4})[\s\r\n]+(?:Name:[\s]*([^\r\n]+))?", re.IGNORECASE),
                re.compile(r"Number:[\s]*(\d{13,19})[\s\r\n]+Exp(?:iry)?:[\s]*(\d{2}/\d{2,4})[\s\r\n]+CVC:[\s]*(\d{3,4})[\s\r\n]+(?:Holder:[\s]*([^\r\n]+))?", re.IGNORECASE)
            ],
            
            # System info formats
            "system_info": [
                # OS version
                re.compile(r"OS:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Computer name
                re.compile(r"Computer(?:\s*Name)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Username
                re.compile(r"User(?:name)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Hardware ID
                re.compile(r"HWID:[\s]*([^\r\n]+)", re.IGNORECASE),
                # IP address
                re.compile(r"IP(?:\s*Address)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Country
                re.compile(r"Country:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Resolution
                re.compile(r"Resolution:[\s]*([^\r\n]+)", re.IGNORECASE),
                # CPU
                re.compile(r"CPU:[\s]*([^\r\n]+)", re.IGNORECASE),
                # RAM
                re.compile(r"RAM:[\s]*([^\r\n]+)", re.IGNORECASE),
                # GPU
                re.compile(r"GPU:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Cookie patterns
            "cookies": [
                re.compile(r"Host:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Domain:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                # Wallet paths
                re.compile(r"Wallet:[\s]*([^\r\n]+\.(?:wallet|dat))", re.IGNORECASE),
                # Specific crypto currencies
                re.compile(r"Bitcoin:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Ethereum:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Litecoin:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Monero:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Specific wallet software
                re.compile(r"Exodus:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Electrum:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Atomic:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Jaxx:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Screenshots often taken by Vidar
            "screenshots": re.compile(r"Screenshot:[\s]*([^\r\n]+\.(?:png|jpg|jpeg|bmp))", re.IGNORECASE)
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
            
        # Quick check for Vidar headers (high confidence)
        if self._patterns["header"].search(text):
            return True, 0.95
            
        # Check for Vidar's distinctive section markers (medium confidence)
        section_score = 0.0
        if self._patterns["section_browser"].search(text):
            section_score += 0.15
        if self._patterns["section_system"].search(text):
            section_score += 0.15
        if self._patterns["section_crypto"].search(text):
            section_score += 0.15
        if self._patterns["section_ftp"].search(text):
            section_score += 0.15
        if self._patterns["section_messenger"].search(text):
            section_score += 0.15
            
        # File name check for common Vidar naming
        if message_data.get("media_path"):
            file_name = os.path.basename(message_data["media_path"])
            if re.search(r"(vidar|vengeance)", file_name, re.IGNORECASE):
                section_score += 0.3
                
        # If we have a reasonable confidence, return true
        return section_score >= self.confidence_threshold, section_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Vidar stealer format message.
        
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
            "credit_cards": [],
            "screenshots": [],      # Vidar often takes screenshots
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
                    
                # Special handling for FTP/Application credentials
                credential_type = "web"
                if "FTP Host" in pattern.pattern:
                    credential_type = "ftp"
                elif "Application" in pattern.pattern:
                    credential_type = "application"
                    
                result["credentials"].append({
                    "url": url,
                    "domain": domain,
                    "username": username,
                    "password": password,
                    "type": credential_type
                })
                
        # Extract credit cards
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
                elif "Computer" in pattern.pattern:
                    system_info["computer_name"] = match.group(1).strip()
                elif "User" in pattern.pattern:
                    system_info["username"] = match.group(1).strip()
                elif "HWID:" in pattern.pattern:
                    system_info["hardware_id"] = match.group(1).strip()
                elif "IP" in pattern.pattern:
                    system_info["ip"] = match.group(1).strip()
                elif "Country:" in pattern.pattern:
                    system_info["country"] = match.group(1).strip()
                elif "Resolution:" in pattern.pattern:
                    system_info["screen_resolution"] = match.group(1).strip()
                elif "CPU:" in pattern.pattern:
                    system_info["cpu"] = match.group(1).strip()
                elif "RAM:" in pattern.pattern:
                    system_info["ram"] = match.group(1).strip()
                elif "GPU:" in pattern.pattern:
                    system_info["gpu"] = match.group(1).strip()
                    
        # Check for enterprise OS
        if system_info.get("os"):
            os_lower = system_info["os"].lower()
            if "enterprise" in os_lower or "business" in os_lower or "server" in os_lower:
                system_info["is_corporate"] = True
                
        # Check for corporate hostname
        if system_info.get("computer_name"):
            hostname = system_info["computer_name"].lower()
            if any(term in hostname for term in ["corp", "ent", "biz", "ltd", "company"]):
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
                pattern_str = pattern.pattern.lower()
                if "bitcoin" in pattern_str:
                    wallet_type = "bitcoin"
                elif "ethereum" in pattern_str:
                    wallet_type = "ethereum"
                elif "litecoin" in pattern_str:
                    wallet_type = "litecoin"
                elif "monero" in pattern_str:
                    wallet_type = "monero"
                elif "exodus" in pattern_str:
                    wallet_type = "exodus"
                elif "electrum" in pattern_str:
                    wallet_type = "electrum"
                elif "atomic" in pattern_str:
                    wallet_type = "atomic"
                elif "jaxx" in pattern_str:
                    wallet_type = "jaxx"
                    
                result["crypto_wallets"].append({
                    "type": wallet_type,
                    "path": wallet_data
                })
                
                # Add to file paths if it looks like a path
                if os.path.sep in wallet_data or wallet_data.endswith(('.dat', '.wallet')):
                    result["file_paths"].append(wallet_data)
                    
        # Extract screenshots
        for match in self._patterns["screenshots"].finditer(text):
            screenshot_path = match.group(1).strip()
            result["screenshots"].append({
                "path": screenshot_path
            })
            result["file_paths"].append(screenshot_path)
                
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "credit_cards", "screenshots", "file_paths"]:
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
        
        # Add bonus to value score for credit cards (Vidar specialty)
        if result["credit_cards"]:
            result["value_score"] = min(100, result["value_score"] * 1.3)  # 30% bonus capped at 100
            
        return result
        
    def calculate_value_score(self, parsed_data: Dict[str, Any]) -> float:
        """
        Calculate value score for parsed data with Vidar-specific scoring.
        
        Args:
            parsed_data: Dictionary with parsed data
            
        Returns:
            Value score (0-100)
        """
        # Use the base value calculation
        score = super().calculate_value_score(parsed_data)
        
        # Add value for credit cards (high value, Vidar specialty)
        for card in parsed_data.get("credit_cards", []):
            # Each credit card is very valuable
            score += 30  # Higher value for Vidar as it specifically targets financial credentials
            
        # Add value for screenshots (Vidar often takes these for additional context)
        if parsed_data.get("screenshots"):
            score += len(parsed_data["screenshots"]) * 5  # 5 points per screenshot
            
        # Cap at 100
        return min(score, 100)
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a Vidar stealer file.
        
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
            "screenshots": [],
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
                    
                # Look for Vidar JSON structure
                if isinstance(data, dict):
                    # Extract credentials
                    if "credentials" in data and isinstance(data["credentials"], list):
                        for cred in data["credentials"]:
                            if isinstance(cred, dict):
                                url = cred.get("URL") or cred.get("url")
                                host = cred.get("Host") or cred.get("host")
                                app = cred.get("App") or cred.get("app") or cred.get("Application") or cred.get("application")
                                username = cred.get("Username") or cred.get("username") or cred.get("User") or cred.get("user")
                                password = cred.get("Password") or cred.get("password") or cred.get("Pass") or cred.get("pass")
                                cred_type = cred.get("Type") or cred.get("type") or "web"
                                
                                if username and password:
                                    domain = None
                                    if url:
                                        domain = self.extract_domain_from_url(url)
                                    elif host:
                                        domain = host
                                    elif app:
                                        domain = app
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
                        
                        # Map Vidar system info fields
                        mapping = {
                            "OS": "os",
                            "os": "os",
                            "ComputerName": "computer_name",
                            "computerName": "computer_name",
                            "Computer": "computer_name",
                            "UserName": "username",
                            "userName": "username",
                            "Username": "username",
                            "User": "username",
                            "HWID": "hardware_id",
                            "hwid": "hardware_id",
                            "IP": "ip",
                            "ip": "ip",
                            "IPAddress": "ip",
                            "ipAddress": "ip",
                            "Country": "country",
                            "country": "country",
                            "Resolution": "screen_resolution",
                            "resolution": "screen_resolution",
                            "screenResolution": "screen_resolution",
                            "CPU": "cpu",
                            "cpu": "cpu",
                            "RAM": "ram",
                            "ram": "ram",
                            "GPU": "gpu",
                            "gpu": "gpu"
                        }
                        
                        for src, dest in mapping.items():
                            if src in system:
                                if isinstance(system[src], str) or isinstance(system[src], bool) or isinstance(system[src], int):
                                    sys_info[dest] = str(system[src])
                                    
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
                                        
                    # Extract screenshots
                    if "screenshots" in data and isinstance(data["screenshots"], list):
                        for screenshot in data["screenshots"]:
                            if isinstance(screenshot, str):
                                result["screenshots"].append({
                                    "path": screenshot
                                })
                                result["file_paths"].append(screenshot)
                            elif isinstance(screenshot, dict):
                                path = screenshot.get("Path") or screenshot.get("path")
                                if path:
                                    result["screenshots"].append({
                                        "path": path
                                    })
                                    result["file_paths"].append(path)
                                    
            elif ext in ['.txt', '.log']:
                # Process as plain text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Use the same parsing logic as for message text
                text_result = self.parse({"text": text})
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "credit_cards", "screenshots", "file_paths", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result
