"""
StealC Stealer parser plugin.

This module implements a parser for the StealC stealer format.
StealC has grown significantly in market share since 2023.
"""

import re
import json
import os
from typing import Dict, Any, Tuple
from src.processing.stealer_plugins.base import StealerParserPlugin

class StealCParser(StealerParserPlugin):
    """Parser for StealC stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "stealc_parser"
        self.value_multiplier = 1.2  # StealC has good credential extraction quality
        
        # StealC specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"Steal[\s]*C|StealC[\s]*Report|StealC[\s]*Log", re.IGNORECASE),
            "section_browser": re.compile(r"\[+[\s]*(?:Browser|Passwords|Autofill|Cards)[\s]*\]+", re.IGNORECASE),
            "section_system": re.compile(r"\[+[\s]*(?:System|System Info|Machine Info)[\s]*\]+", re.IGNORECASE),
            "section_crypto": re.compile(r"\[+[\s]*(?:Crypto|Wallets|Coins)[\s]*\]+", re.IGNORECASE),
            "section_files": re.compile(r"\[+[\s]*(?:Files|Stolen Files|Grabbed)[\s]*\]+", re.IGNORECASE),
            "section_apps": re.compile(r"\[+[\s]*(?:Applications|Software|Apps)[\s]*\]+", re.IGNORECASE),
            
            # StealC logo
            "stealc_logo": re.compile(r"SSSSS[\s]*TTTTT[\s]*EEEEE[\s]*AAAAA[\s]*L[\s]*CCCCC|S[\s]*T[\s]*E[\s]*A[\s]*L[\s]*C", re.IGNORECASE),
            
            # Credential formats specific to StealC
            "credentials": [
                # URL/Username/Password format
                re.compile(r"URL:[\s]*(https?://[^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Host/Username/Password format
                re.compile(r"Host:[\s]*([^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE),
                # Origin/Username/Password format
                re.compile(r"Origin:[\s]*([^\s\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\s\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\s\r\n]+)", re.IGNORECASE)
            ],
            
            # Autofill / form data (StealC specialty)
            "autofill": [
                re.compile(r"Name:[\s]*([^\s\r\n]+)[\s\r\n]+Value:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Credit card formats
            "credit_cards": [
                re.compile(r"Number:[\s]*(\d{13,19})[\s\r\n]+Expiry:[\s]*(\d{2}/\d{2,4})[\s\r\n]+CVC:[\s]*(\d{3,4})[\s\r\n]+(?:Holder:[\s]*([^\r\n]+))?", re.IGNORECASE),
                re.compile(r"Card:[\s]*(\d{13,19})[\s\r\n]+Exp(?:iry)?:[\s]*(\d{2}/\d{2,4})[\s\r\n]+CVV:[\s]*(\d{3,4})[\s\r\n]+(?:Name:[\s]*([^\r\n]+))?", re.IGNORECASE)
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
                # Display resolution
                re.compile(r"Resolution:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Language
                re.compile(r"Language:[\s]*([^\r\n]+)", re.IGNORECASE),
                # IP address
                re.compile(r"IP(?:\s*Address)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Country
                re.compile(r"Country:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Timezone
                re.compile(r"Timezone:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Date/Time
                re.compile(r"Date(?:/Time)?:[\s]*([^\r\n]+)", re.IGNORECASE),
                # Antivirus
                re.compile(r"Antivirus:[\s]*([^\r\n]+)", re.IGNORECASE),
                # CPU
                re.compile(r"CPU:[\s]*([^\r\n]+)", re.IGNORECASE),
                # GPU
                re.compile(r"GPU:[\s]*([^\r\n]+)", re.IGNORECASE),
                # RAM
                re.compile(r"RAM:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Installed software (often detailed in StealC)
            "installed_software": re.compile(r"Software:[\s]*(.+?)(?=\[|\Z)", re.IGNORECASE | re.DOTALL),
            
            # Cookie patterns
            "cookies": [
                re.compile(r"Host:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"Domain:[\s]*([^\r\n]+)[\s\r\n]+Cookie:[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                re.compile(r"Wallet:[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"(?:Bitcoin|Ethereum|Ripple|Monero|Litecoin|Dogecoin):[\s]*([^\r\n]+)", re.IGNORECASE),
                re.compile(r"(?:Exodus|Jaxx|Atomic|Electrum|Metamask):[\s]*([^\r\n]+)", re.IGNORECASE)
            ],
            
            # File grabber patterns (often detailed in StealC)
            "files": [
                re.compile(r"File:[\s]*([^\r\n]+\.(?:txt|pdf|docx?|xlsx?|jpg|png))", re.IGNORECASE),
                re.compile(r"Grabbed:[\s]*([^\r\n]+\.(?:txt|pdf|docx?|xlsx?|jpg|png))", re.IGNORECASE)
            ],
            
            # Gaming/application credentials (StealC specialty)
            "game_creds": re.compile(r"Game:[\s]*([^\r\n]+)[\s\r\n]+User(?:name)?:[\s]*([^\r\n]+)[\s\r\n]+Pass(?:word)?:[\s]*([^\r\n]+)", re.IGNORECASE)
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
            
        # Quick check for StealC headers or logo (high confidence)
        if self._patterns["header"].search(text) or self._patterns["stealc_logo"].search(text):
            return True, 0.95
            
        # Check for StealC's distinctive section markers (medium confidence)
        section_score = 0.0
        if self._patterns["section_browser"].search(text):
            section_score += 0.15
        if self._patterns["section_system"].search(text):
            section_score += 0.15
        if self._patterns["section_crypto"].search(text):
            section_score += 0.15
        if self._patterns["section_files"].search(text):
            section_score += 0.15
        if self._patterns["section_apps"].search(text):
            section_score += 0.15
            
        # Check for game credentials (more specific to StealC)
        if self._patterns["game_creds"].search(text):
            section_score += 0.25
            
        # File name check for common StealC naming
        if message_data.get("media_path"):
            file_name = os.path.basename(message_data["media_path"])
            if re.search(r"(steal[\s_-]?c|stealc)", file_name, re.IGNORECASE):
                section_score += 0.3
                
        # If we have a reasonable confidence, return true
        return section_score >= self.confidence_threshold, section_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse StealC stealer format message.
        
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
            "autofill_data": [],  # StealC specialty (form data)
            "game_credentials": [],  # StealC specialty (gaming credentials)
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
                    
                result["credentials"].append({
                    "url": url,
                    "domain": domain,
                    "username": username,
                    "password": password
                })
                
        # Extract game credentials
        for match in self._patterns["game_creds"].finditer(text):
            game, username, password = match.groups()
            result["game_credentials"].append({
                "game": game.strip(),
                "username": username.strip(),
                "password": password.strip()
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
                    
        # Extract autofill data
        for pattern in self._patterns["autofill"]:
            for match in pattern.finditer(text):
                name, value = match.groups()
                result["autofill_data"].append({
                    "name": name.strip(),
                    "value": value.strip()
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
                elif "Resolution:" in pattern.pattern:
                    system_info["screen_resolution"] = match.group(1).strip()
                elif "Language:" in pattern.pattern:
                    system_info["language"] = match.group(1).strip()
                elif "IP" in pattern.pattern:
                    system_info["ip"] = match.group(1).strip()
                elif "Country:" in pattern.pattern:
                    system_info["country"] = match.group(1).strip()
                elif "Timezone:" in pattern.pattern:
                    system_info["timezone"] = match.group(1).strip()
                elif "Date" in pattern.pattern:
                    system_info["date"] = match.group(1).strip()
                elif "Antivirus:" in pattern.pattern:
                    system_info["antivirus"] = match.group(1).strip()
                elif "CPU:" in pattern.pattern:
                    system_info["cpu"] = match.group(1).strip()
                elif "GPU:" in pattern.pattern:
                    system_info["gpu"] = match.group(1).strip()
                elif "RAM:" in pattern.pattern:
                    system_info["ram"] = match.group(1).strip()
                    
        # Extract installed software
        match = self._patterns["installed_software"].search(text)
        if match:
            software_text = match.group(1).strip()
            software_list = [s.strip() for s in software_text.split('\n') if s.strip()]
            if software_list:
                system_info["installed_software"] = software_list
                
                # Check for enterprise software indicators
                enterprise_software = ["citrix", "vpn", "symantec", "mcafee", "enterprise", "sql server", 
                                    "oracle", "sap", "jira", "confluence", "salesforce", "workday"]
                                    
                for software in software_list:
                    if any(e in software.lower() for e in enterprise_software):
                        system_info["is_corporate"] = True
                        break
                    
        # Check for enterprise OS
        if system_info.get("os"):
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
                pattern_str = pattern.pattern.lower()
                if "bitcoin" in pattern_str:
                    wallet_type = "bitcoin"
                elif "ethereum" in pattern_str:
                    wallet_type = "ethereum"
                elif "ripple" in pattern_str:
                    wallet_type = "ripple"
                elif "monero" in pattern_str:
                    wallet_type = "monero"
                elif "litecoin" in pattern_str:
                    wallet_type = "litecoin"
                elif "dogecoin" in pattern_str:
                    wallet_type = "dogecoin"
                elif "exodus" in pattern_str:
                    wallet_type = "exodus"
                elif "jaxx" in pattern_str:
                    wallet_type = "jaxx"
                elif "atomic" in pattern_str:
                    wallet_type = "atomic"
                elif "electrum" in pattern_str:
                    wallet_type = "electrum"
                elif "metamask" in pattern_str:
                    wallet_type = "metamask"
                    
                result["crypto_wallets"].append({
                    "type": wallet_type,
                    "path": wallet_data
                })
                
                # Add to file paths if it looks like a path
                if os.path.sep in wallet_data or wallet_data.endswith(('.dat', '.wallet')):
                    result["file_paths"].append(wallet_data)
                    
        # Extract file paths
        for pattern in self._patterns["files"]:
            for match in pattern.finditer(text):
                file_path = match.group(1).strip()
                if file_path not in result["file_paths"]:
                    result["file_paths"].append(file_path)
                    
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "credit_cards", "autofill_data", "game_credentials", "file_paths"]:
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
            
        # Add bonus for game credentials
        if result["game_credentials"]:
            result["value_score"] = min(100, result["value_score"] * 1.1)  # 10% bonus capped at 100
            
        return result
        
    def calculate_value_score(self, parsed_data: Dict[str, Any]) -> float:
        """
        Calculate value score for parsed data with StealC-specific scoring.
        
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
            
        # Add value for game credentials (medium value)
        for cred in parsed_data.get("game_credentials", []):
            # Gaming accounts often have payment info associated
            game = cred.get("game", "").lower()
            if any(platform in game for platform in ["steam", "epic", "ubisoft", "origin", "blizzard"]):
                score += 15  # Higher value for major gaming platforms
            else:
                score += 8   # Lower value for other gaming accounts
                
        # Add value for autofill data (varies)
        for data in parsed_data.get("autofill_data", []):
            name = data.get("name", "").lower()
            # Look for high-value autofill fields
            if any(field in name for field in ["credit", "card", "cvv", "ssn", "social", "tax", "passport"]):
                score += 10  # High value personal data
            elif any(field in name for field in ["address", "phone", "birth", "license", "id"]):
                score += 5   # Medium value personal data
                
        # Cap at 100
        return min(score, 100)
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a StealC stealer file.
        
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
            "autofill_data": [],
            "game_credentials": [],
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
                    
                # Look for StealC JSON structure
                if isinstance(data, dict):
                    # Extract credentials
                    if "credentials" in data and isinstance(data["credentials"], list):
                        for cred in data["credentials"]:
                            if isinstance(cred, dict):
                                url = cred.get("URL") or cred.get("url")
                                host = cred.get("Host") or cred.get("host")
                                username = cred.get("Username") or cred.get("username") or cred.get("User") or cred.get("user")
                                password = cred.get("Password") or cred.get("password") or cred.get("Pass") or cred.get("pass")
                                
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
                                        "password": password
                                    })
                                    
                    # Extract game credentials
                    if "games" in data and isinstance(data["games"], list):
                        for game in data["games"]:
                            if isinstance(game, dict):
                                game_name = game.get("Game") or game.get("game") or game.get("Name") or game.get("name")
                                username = game.get("Username") or game.get("username") or game.get("User") or game.get("user")
                                password = game.get("Password") or game.get("password") or game.get("Pass") or game.get("pass")
                                
                                if game_name and username and password:
                                    result["game_credentials"].append({
                                        "game": game_name,
                                        "username": username,
                                        "password": password
                                    })
                                    
                    # Extract credit cards
                    if "cards" in data and isinstance(data["cards"], list):
                        for card in data["cards"]:
                            if isinstance(card, dict):
                                number = card.get("Number") or card.get("number") or card.get("Card") or card.get("card")
                                expiry = card.get("Expiry") or card.get("expiry") or card.get("Exp") or card.get("exp")
                                cvv = card.get("CVC") or card.get("cvc") or card.get("CVV") or card.get("cvv")
                                holder = card.get("Holder") or card.get("holder") or card.get("Name") or card.get("name")
                                
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
                                    
                    # Extract autofill data
                    if "autofill" in data and isinstance(data["autofill"], list):
                        for item in data["autofill"]:
                            if isinstance(item, dict):
                                name = item.get("Name") or item.get("name")
                                value = item.get("Value") or item.get("value")
                                
                                if name and value:
                                    result["autofill_data"].append({
                                        "name": name,
                                        "value": value
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
                        
                        # Map StealC system info fields
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
                            "HardwareID": "hardware_id",
                            "Resolution": "screen_resolution",
                            "resolution": "screen_resolution",
                            "Language": "language",
                            "language": "language",
                            "IP": "ip",
                            "ip": "ip",
                            "IPAddress": "ip",
                            "Country": "country",
                            "country": "country",
                            "Timezone": "timezone",
                            "timezone": "timezone",
                            "Date": "date",
                            "date": "date",
                            "Antivirus": "antivirus",
                            "antivirus": "antivirus",
                            "CPU": "cpu",
                            "cpu": "cpu",
                            "GPU": "gpu",
                            "gpu": "gpu",
                            "RAM": "ram",
                            "ram": "ram"
                        }
                        
                        for src, dest in mapping.items():
                            if src in system:
                                if isinstance(system[src], str) or isinstance(system[src], bool) or isinstance(system[src], int):
                                    sys_info[dest] = str(system[src])
                                    
                        # Check for installed software
                        if "Software" in system and isinstance(system["Software"], list):
                            sys_info["installed_software"] = system["Software"]
                            
                            # Check for enterprise software indicators
                            enterprise_software = ["citrix", "vpn", "symantec", "mcafee", "enterprise", "sql server", 
                                                "oracle", "sap", "jira", "confluence", "salesforce", "workday"]
                                                
                            for software in system["Software"]:
                                if isinstance(software, str) and any(e in software.lower() for e in enterprise_software):
                                    sys_info["is_corporate"] = True
                                    break
                                    
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
                                        
                    # Extract grabbed files
                    if "files" in data and isinstance(data["files"], list):
                        for file in data["files"]:
                            if isinstance(file, str) and file not in result["file_paths"]:
                                result["file_paths"].append(file)
                            elif isinstance(file, dict):
                                path = file.get("Path") or file.get("path")
                                if path and path not in result["file_paths"]:
                                    result["file_paths"].append(path)
                                    
            elif ext in ['.txt', '.log']:
                # Process as plain text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Use the same parsing logic as for message text
                text_result = self.parse({"text": text})
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "credit_cards", "autofill_data", "game_credentials", "file_paths", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result
