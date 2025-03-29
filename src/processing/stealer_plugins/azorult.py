"""
Azorult Stealer parser plugin.

This module implements a parser for the Azorult stealer format.
"""

import re
import json
import os
from typing import Dict, List, Any, Tuple, Optional
from src.processing.stealer_plugins.base import StealerParserPlugin

class AzorultParser(StealerParserPlugin):
    """Parser for Azorult stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "azorult_parser"
        # Azorult data typically contains valuable credit card information
        self.value_multiplier = 1.35  
        
        # Azorult specific patterns
        self._patterns = {
            # Headers and section markers
            "header": re.compile(r"AZORult Report|Azorult Stealer|AZR(?:[\s-]*[\d\.]+)? Report", re.IGNORECASE),
            "section_data": re.compile(r"\[(?:DATA|PASSWORDS|LOGINS|CREDENTIALS)\]", re.IGNORECASE),
            "section_system": re.compile(r"\[(?:SYSTEM|PC|MACHINE)\]", re.IGNORECASE),
            "section_crypto": re.compile(r"\[(?:WALLETS|CRYPTO|CRYPTOCURRENCY)\]", re.IGNORECASE),
            "section_cards": re.compile(r"\[(?:CARDS|CREDIT|CREDIT CARDS|PAYMENT)\]", re.IGNORECASE),
            
            # Credential formats specific to Azorult
            "credentials": [
                # URL / Login / Password format
                re.compile(r"URL:[\s]*(.+?)[\s\r\n]+LOGIN:[\s]*(.+?)[\s\r\n]+PASSWORD:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # HOST / USER / PASS format
                re.compile(r"HOST:[\s]*(.+?)[\s\r\n]+USER:[\s]*(.+?)[\s\r\n]+PASS:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # WEBSITE / LOGIN / PASSWORD format
                re.compile(r"WEBSITE:[\s]*(.+?)[\s\r\n]+LOGIN:[\s]*(.+?)[\s\r\n]+PASSWORD:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # SOFTWARE / USER / PASS format (for desktop applications)
                re.compile(r"SOFTWARE:[\s]*(.+?)[\s\r\n]+USER:[\s]*(.+?)[\s\r\n]+PASS:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE)
            ],
            
            # System info formats
            "system_info": [
                # OS version
                re.compile(r"OS:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # PC Name
                re.compile(r"PC[\s-]*NAME:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # User
                re.compile(r"USER(?:NAME)?:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # IP address
                re.compile(r"IP(?:[\s-]*ADDRESS)?:[\s]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\r\n]|$)", re.IGNORECASE),
                # Country
                re.compile(r"COUNTRY:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # Screen resolution
                re.compile(r"RESOLUTION:[\s]*(\d+x\d+)(?:[\r\n]|$)", re.IGNORECASE),
                # Antivirus
                re.compile(r"ANTIVIRUS:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE)
            ],
            
            # Credit card patterns (Azorult often steals card data)
            "credit_cards": [
                # Typical credit card format
                re.compile(r"CARD[\s-]*NUMBER:[\s]*(\d{4}[\s-]*\d{4}[\s-]*\d{4}[\s-]*\d{4})[\s\r\n]+EXP(?:IRY)?[\s-]*(?:DATE)?:[\s]*(\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(\d{3,4})(?:[\r\n]|$)", re.IGNORECASE),
                # With cardholder
                re.compile(r"CARD[\s-]*NUMBER:[\s]*(\d{4}[\s-]*\d{4}[\s-]*\d{4}[\s-]*\d{4})[\s\r\n]+EXP(?:IRY)?[\s-]*(?:DATE)?:[\s]*(\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(\d{3,4})[\s\r\n]+(?:CARD)?[\s-]*HOLDER:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # Simplified format
                re.compile(r"CARD:[\s]*(\d{4}[\s-]*\d{4}[\s-]*\d{4}[\s-]*\d{4})[\s\r\n]+EXP:[\s]*(\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(\d{3,4})(?:[\r\n]|$)", re.IGNORECASE)
            ],
            
            # Crypto wallet patterns
            "crypto_wallets": [
                # Bitcoin wallets
                re.compile(r"BITCOIN(?:[\s-]*WALLET)?:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # Ethereum wallets
                re.compile(r"ETHEREUM(?:[\s-]*WALLET)?:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # Generic wallet or wallet seed
                re.compile(r"(?:CRYPTO)?[\s-]*WALLET(?:[\s-]*SEED)?:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # Wallet seed phrase
                re.compile(r"SEED[\s-]*PHRASE:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE)
            ],
            
            # Cookies
            "cookies": [
                # Domain and cookie value
                re.compile(r"HOST:[\s]*(.+?)[\s\r\n]+COOKIE:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE),
                # URL and cookie value
                re.compile(r"URL:[\s]*(.+?)[\s\r\n]+COOKIE:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE)
            ],
            
            # FTP credentials (often found in Azorult logs)
            "ftp_credentials": [
                re.compile(r"FTP[\s-]*HOST:[\s]*(.+?)[\s\r\n]+USER(?:NAME)?:[\s]*(.+?)[\s\r\n]+PASS(?:WORD)?:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE)
            ],
            
            # File paths (Azorult often logs important file paths)
            "file_paths": [
                re.compile(r"PATH:[\s]*(.+?)(?:[\r\n]|$)", re.IGNORECASE)
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
            
        # Track matches for debug data
        if self.debug_mode:
            self.debug_data["fingerprinting"] = []
            
        # Quick check for Azorult headers (high confidence)
        if self._patterns["header"].search(text):
            if self.debug_mode:
                self.debug_data["fingerprinting"].append({
                    "pattern": "header",
                    "matched": True,
                    "confidence": 0.8
                })
            return True, 0.8
            
        # Check for section markers (medium confidence)
        section_score = 0.0
        section_markers = ["section_data", "section_system", "section_crypto", "section_cards"]
        for marker in section_markers:
            if self._patterns[marker].search(text):
                section_score += 0.15
                if self.debug_mode:
                    self.debug_data["fingerprinting"].append({
                        "pattern": marker,
                        "matched": True,
                        "confidence": 0.15
                    })
                    
        # Check for typical Azorult credential patterns
        cred_score = 0.0
        for pattern in self._patterns["credentials"]:
            if pattern.search(text):
                cred_score += 0.2
                if self.debug_mode:
                    self.debug_data["fingerprinting"].append({
                        "pattern": "credential_pattern",
                        "matched": True,
                        "confidence": 0.2
                    })
                break
                
        # Check for credit card patterns (very specific to Azorult)
        card_score = 0.0
        for pattern in self._patterns["credit_cards"]:
            if pattern.search(text):
                card_score += 0.3
                if self.debug_mode:
                    self.debug_data["fingerprinting"].append({
                        "pattern": "credit_card_pattern",
                        "matched": True,
                        "confidence": 0.3
                    })
                break
                
        # Combined score
        total_score = section_score + cred_score + card_score
        
        # If we have a reasonable confidence, return true
        can_parse = total_score >= self.confidence_threshold
        
        if self.debug_mode:
            self.debug_data["fingerprinting"].append({
                "total_score": total_score,
                "threshold": self.confidence_threshold,
                "can_parse": can_parse
            })
            
        return can_parse, total_score
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse Azorult stealer format message.
        
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
            "ftp_credentials": [],
            "file_paths": [],
            "parsing_errors": []
        }
        
        text = message_data.get("text", "")
        if not text:
            return result
            
        if self.debug_mode:
            self.debug_data["extraction_details"] = {
                "credentials": 0,
                "cookies": 0,
                "system_info": 0,
                "crypto_wallets": 0,
                "credit_cards": 0,
                "ftp_credentials": 0,
                "file_paths": 0
            }
            
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
                
                if self.debug_mode:
                    self.debug_data["extraction_details"]["credentials"] += 1
                
        # Extract system information
        system_info = {}
        for pattern in self._patterns["system_info"]:
            match = pattern.search(text)
            if match:
                value = match.group(1).strip()
                
                if pattern.pattern.startswith("OS:"):
                    system_info["os"] = value
                elif pattern.pattern.startswith("PC[\s-]*NAME:"):
                    system_info["computer_name"] = value
                elif pattern.pattern.startswith("USER(?:NAME)?:"):
                    system_info["username"] = value
                elif pattern.pattern.startswith("IP(?:[\s-]*ADDRESS)?:"):
                    system_info["ip"] = value
                elif pattern.pattern.startswith("COUNTRY:"):
                    system_info["country"] = value
                elif pattern.pattern.startswith("RESOLUTION:"):
                    system_info["screen_resolution"] = value
                elif pattern.pattern.startswith("ANTIVIRUS:"):
                    system_info["antivirus"] = value
                    
                if self.debug_mode:
                    self.debug_data["extraction_details"]["system_info"] += 1
        
        # Check for enterprise indicators
        if system_info:
            # Check for enterprise OS
            os_info = system_info.get("os", "").lower()
            antivirus = system_info.get("antivirus", "").lower()
            
            # Enterprise detection heuristics
            is_enterprise = (
                "enterprise" in os_info or 
                "server" in os_info or 
                "domain" in os_info or
                "endpoint" in antivirus or
                "enterprise" in antivirus
            )
            
            if is_enterprise:
                system_info["is_corporate"] = True
                
            result["system_info"] = system_info
                
        # Extract credit card information
        for pattern in self._patterns["credit_cards"]:
            for match in pattern.finditer(text):
                if len(match.groups()) == 3:
                    # Standard format
                    card_number, expiry, cvv = match.groups()
                    result["credit_cards"].append({
                        "number": card_number.replace(" ", "").replace("-", ""),
                        "expiry": expiry,
                        "cvv": cvv,
                        "holder": None
                    })
                elif len(match.groups()) == 4:
                    # With cardholder
                    card_number, expiry, cvv, holder = match.groups()
                    result["credit_cards"].append({
                        "number": card_number.replace(" ", "").replace("-", ""),
                        "expiry": expiry,
                        "cvv": cvv,
                        "holder": holder
                    })
                    
                if self.debug_mode:
                    self.debug_data["extraction_details"]["credit_cards"] += 1
                    
        # Extract cookies
        for pattern in self._patterns["cookies"]:
            for match in pattern.finditer(text):
                host_or_url, cookie_value = match.groups()
                
                # Extract domain from URL or use host directly
                if host_or_url.startswith(('http://', 'https://')):
                    domain = self.extract_domain_from_url(host_or_url)
                else:
                    domain = host_or_url
                    
                result["cookies"].append({
                    "domain": domain,
                    "value": cookie_value.strip()
                })
                
                if self.debug_mode:
                    self.debug_data["extraction_details"]["cookies"] += 1
                    
        # Extract crypto wallet information
        for pattern in self._patterns["crypto_wallets"]:
            for match in pattern.finditer(text):
                wallet_info = match.group(1).strip()
                wallet_type = "unknown"
                
                # Determine wallet type from pattern
                if pattern.pattern.startswith("BITCOIN"):
                    wallet_type = "bitcoin"
                elif pattern.pattern.startswith("ETHEREUM"):
                    wallet_type = "ethereum"
                elif pattern.pattern.startswith("SEED[\s-]*PHRASE:"):
                    # This is a seed phrase, check content for wallet type hints
                    if len(wallet_info.split()) in [12, 24]:
                        wallet_type = "seed_phrase"
                        
                # Try to detect wallet type from content
                if wallet_type == "unknown":
                    if wallet_info.startswith("0x") and len(wallet_info) == 42:
                        wallet_type = "ethereum"
                    elif (wallet_info.startswith("1") or wallet_info.startswith("3") or 
                          wallet_info.startswith("bc1")) and len(wallet_info) >= 26:
                        wallet_type = "bitcoin"
                        
                result["crypto_wallets"].append({
                    "type": wallet_type,
                    "value": wallet_info,
                    "is_seed_phrase": wallet_type == "seed_phrase"
                })
                
                if self.debug_mode:
                    self.debug_data["extraction_details"]["crypto_wallets"] += 1
                    
        # Extract FTP credentials
        for pattern in self._patterns["ftp_credentials"]:
            for match in pattern.finditer(text):
                host, username, password = match.groups()
                
                # Add to both credentials and specific FTP collection
                result["credentials"].append({
                    "domain": host,
                    "username": username,
                    "password": password,
                    "protocol": "ftp"
                })
                
                result["ftp_credentials"].append({
                    "host": host,
                    "username": username,
                    "password": password
                })
                
                if self.debug_mode:
                    self.debug_data["extraction_details"]["ftp_credentials"] += 1
                    
        # Extract important file paths
        for pattern in self._patterns["file_paths"]:
            for match in pattern.finditer(text):
                file_path = match.group(1).strip()
                result["file_paths"].append(file_path)
                
                if self.debug_mode:
                    self.debug_data["extraction_details"]["file_paths"] += 1
                    
        # Parse attachments if available
        if message_data.get("has_media") and message_data.get("media_path"):
            try:
                file_result = self.parse_file(message_data["media_path"])
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", 
                            "credit_cards", "ftp_credentials"]:
                    if key in file_result and file_result[key]:
                        result[key].extend(file_result[key])
                        if self.debug_mode and key in self.debug_data["extraction_details"]:
                            self.debug_data["extraction_details"][key] += len(file_result[key])
                        
                # Merge system info (dictionary)
                if file_result.get("system_info"):
                    result["system_info"].update(file_result["system_info"])
                    if self.debug_mode:
                        self.debug_data["extraction_details"]["system_info"] += 1
                    
                # Add any parsing errors
                if file_result.get("parsing_errors"):
                    result["parsing_errors"].extend(file_result["parsing_errors"])
            except Exception as e:
                error_msg = f"Failed to parse attached file: {str(e)}"
                result["parsing_errors"].append(error_msg)
                
        # Calculate value score
        result["value_score"] = self.calculate_value_score(result)
        
        if self.debug_mode:
            self.debug_data["value_calculation"] = {
                "base_score": result["value_score"] / self.value_multiplier,
                "multiplier": self.value_multiplier,
                "final_score": result["value_score"]
            }
            
        return result
        
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse an Azorult file.
        
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
            "ftp_credentials": [],
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
                    
                # Look for Azorult JSON structure
                if isinstance(data, dict):
                    # Extract credentials
                    if "credentials" in data and isinstance(data["credentials"], list):
                        for cred in data["credentials"]:
                            if isinstance(cred, dict):
                                url = cred.get("URL") or cred.get("url") or cred.get("Host") or cred.get("host")
                                username = (cred.get("Username") or cred.get("username") or 
                                           cred.get("Login") or cred.get("login") or
                                           cred.get("User") or cred.get("user"))
                                password = (cred.get("Password") or cred.get("password") or 
                                           cred.get("Pass") or cred.get("pass"))
                                
                                if username and password:
                                    domain = None
                                    if url:
                                        if url.startswith(('http://', 'https://')):
                                            domain = self.extract_domain_from_url(url)
                                        else:
                                            domain = url
                                    else:
                                        domain = self.extract_domain_from_username(username)
                                        
                                    result["credentials"].append({
                                        "url": url if url and url.startswith(('http://', 'https://')) else None,
                                        "domain": domain,
                                        "username": username,
                                        "password": password
                                    })
                                    
                    # Extract cookies
                    if "cookies" in data and isinstance(data["cookies"], list):
                        for cookie in data["cookies"]:
                            if isinstance(cookie, dict):
                                domain = (cookie.get("Domain") or cookie.get("domain") or 
                                         cookie.get("Host") or cookie.get("host"))
                                value = (cookie.get("Value") or cookie.get("value") or 
                                        cookie.get("Cookie") or cookie.get("cookie"))
                                
                                if domain and value:
                                    result["cookies"].append({
                                        "domain": domain,
                                        "value": value
                                    })
                                    
                    # Extract system info
                    if "system" in data and isinstance(data["system"], dict):
                        system = data["system"]
                        sys_info = {}
                        
                        # Map common Azorult system info fields
                        mapping = {
                            "OS": "os", 
                            "os": "os",
                            "ComputerName": "computer_name",
                            "computerName": "computer_name",
                            "PCName": "computer_name",
                            "UserName": "username",
                            "userName": "username",
                            "user": "username",
                            "IP": "ip",
                            "ip": "ip",
                            "IPAddress": "ip",
                            "Country": "country",
                            "country": "country",
                            "Antivirus": "antivirus",
                            "antivirus": "antivirus",
                            "Resolution": "screen_resolution",
                            "resolution": "screen_resolution"
                        }
                        
                        for src, dest in mapping.items():
                            if src in system:
                                sys_info[dest] = system[src]
                                
                        if sys_info:
                            result["system_info"] = sys_info
                            
                    # Extract credit cards
                    if "cards" in data and isinstance(data["cards"], list):
                        for card in data["cards"]:
                            if isinstance(card, dict):
                                number = (card.get("Number") or card.get("number") or 
                                         card.get("CardNumber") or card.get("cardNumber"))
                                expiry = (card.get("Expiry") or card.get("expiry") or 
                                         card.get("ExpiryDate") or card.get("expiryDate") or
                                         card.get("Exp") or card.get("exp"))
                                cvv = card.get("CVV") or card.get("cvv")
                                holder = (card.get("Holder") or card.get("holder") or 
                                         card.get("CardHolder") or card.get("cardHolder"))
                                
                                if number:
                                    result["credit_cards"].append({
                                        "number": number.replace(" ", "").replace("-", ""),
                                        "expiry": expiry,
                                        "cvv": cvv,
                                        "holder": holder
                                    })
                                    
            elif ext in ['.txt', '.log']:
                # Process as plain text
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Use the same parsing logic as for message text
                text_result = self.parse({"text": text})
                
                # Merge results
                for key in ["credentials", "cookies", "crypto_wallets", "file_paths", 
                            "credit_cards", "ftp_credentials", "parsing_errors"]:
                    if key in text_result and text_result[key]:
                        result[key].extend(text_result[key])
                        
                # Merge system info (dictionary)
                if text_result.get("system_info"):
                    result["system_info"].update(text_result["system_info"])
                    
        except Exception as e:
            result["parsing_errors"].append(f"Error parsing file {file_path}: {str(e)}")
            
        return result

    def calculate_value_score(self, parsed_data: Dict[str, Any]) -> float:
        """
        Calculate value score for Azorult data.
        
        Overrides the base implementation to add specific scoring rules.
        
        Args:
            parsed_data: Dictionary with parsed data
            
        Returns:
            Value score (0-100)
        """
        # Start with base implementation
        score = super().calculate_value_score(parsed_data)
        
        # Add Azorult-specific scoring: high value for credit card data
        for card in parsed_data.get("credit_cards", []):
            card_score = 25  # Base score for any card
            
            # Add more points for complete card info
            if card.get("cvv") and card.get("expiry"):
                card_score += 10
                
            # Add more points for cardholder info
            if card.get("holder"):
                card_score += 5
                
            score += card_score
            
        # FTP credentials are valuable for lateral movement
        for ftp in parsed_data.get("ftp_credentials", []):
            score += 15
            
        # Cap at 100 and apply multiplier
        adjusted_score = min(score, 100) * self.value_multiplier
        return min(adjusted_score, 100)  # Ensure we don't exceed 100
