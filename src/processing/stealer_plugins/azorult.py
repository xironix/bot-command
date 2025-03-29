"""
Azorult Stealer parser plugin.

This module implements a parser for the Azorult stealer format.
"""

import re
import json
import os
import logging
from typing import Dict, List, Any, Tuple, Optional
from src.processing.stealer_plugins.base import StealerParserPlugin
from src.processing.parser_utils import (
    FlexiblePattern, PatternGroup, EnhancedFileHandler,
    validate_credentials, validate_system_info, validate_cookies
)

logger = logging.getLogger(__name__)

class AzorultParser(StealerParserPlugin):
    """Parser for Azorult stealer output."""
    
    def __init__(self):
        super().__init__()
        self.name = "azorult_parser"
        # Azorult data typically contains valuable credit card information
        self.value_multiplier = 1.35
        self.enhanced_file_handler = EnhancedFileHandler()
        
        # Initialize pattern groups for different data types
        self._init_patterns()
        
    def _init_patterns(self):
        """Initialize flexible pattern matching."""
        # Header detection patterns (high priority for identification)
        self.header_patterns = PatternGroup("headers")
        self.header_patterns.add_pattern(
            FlexiblePattern("azorult_header", priority=10)
            .add_regex(r"AZORult(?:[\s-]*[\d\.]+)?(?:\s+Report|\s+Stealer|\s+Logs|\s+Results)", re.IGNORECASE)
            .add_regex(r"AZR(?:[\s-]*[\d\.]+)?\s+Report", re.IGNORECASE)
        )
        
        # Section marker patterns (medium priority)
        self.section_patterns = PatternGroup("sections")
        self.section_patterns.add_pattern(
            FlexiblePattern("data_section", priority=5)
            .add_regex(r"\[(?:DATA|PASSWORDS|LOGINS|CREDENTIALS)\]", re.IGNORECASE)
        )
        self.section_patterns.add_pattern(
            FlexiblePattern("system_section", priority=5)
            .add_regex(r"\[(?:SYSTEM|PC|MACHINE)\]", re.IGNORECASE)
        )
        self.section_patterns.add_pattern(
            FlexiblePattern("crypto_section", priority=5)
            .add_regex(r"\[(?:WALLETS|CRYPTO|CRYPTOCURRENCY)\]", re.IGNORECASE)
        )
        self.section_patterns.add_pattern(
            FlexiblePattern("cards_section", priority=5)
            .add_regex(r"\[(?:CARDS|CREDIT|CREDIT CARDS|PAYMENT)\]", re.IGNORECASE)
        )
        
        # Credential patterns (multiple formats)
        self.credential_patterns = PatternGroup("credentials")
        
        # URL / LOGIN / PASSWORD format
        self.credential_patterns.add_pattern(
            FlexiblePattern("url_login_pass", priority=5)
            .add_regex(r"(?:URL|HOST|WEBSITE)[\s:]+(.+?)[\s\r\n]+(?:LOGIN|USER|USERNAME)[\s:]+(.+?)[\s\r\n]+(?:PASSWORD|PASS|PWD)[\s:]+(.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"URL:[\s]*(?P<url>.+?)[\s\r\n]+LOGIN:[\s]*(?P<username>.+?)[\s\r\n]+PASSWORD:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"HOST:[\s]*(?P<domain>.+?)[\s\r\n]+USER:[\s]*(?P<username>.+?)[\s\r\n]+PASS:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"WEBSITE:[\s]*(?P<domain>.+?)[\s\r\n]+LOGIN:[\s]*(?P<username>.+?)[\s\r\n]+PASSWORD:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
        )
        
        # SOFTWARE / USER / PASS format (for desktop applications)
        self.credential_patterns.add_pattern(
            FlexiblePattern("software_user_pass", priority=4)
            .add_regex(r"SOFTWARE:[\s]*(?P<software>.+?)[\s\r\n]+USER:[\s]*(?P<username>.+?)[\s\r\n]+PASS:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"APPLICATION:[\s]*(?P<software>.+?)[\s\r\n]+USERNAME:[\s]*(?P<username>.+?)[\s\r\n]+PASSWORD:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
        )
        
        # FTP specific credentials
        self.credential_patterns.add_pattern(
            FlexiblePattern("ftp_credentials", priority=6)
            .add_regex(r"FTP[\s-]*HOST:[\s]*(?P<host>.+?)[\s\r\n]+USER(?:NAME)?:[\s]*(?P<username>.+?)[\s\r\n]+PASS(?:WORD)?:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"FTP[\s-]*SERVER:[\s]*(?P<host>.+?)[\s\r\n]+LOGIN:[\s]*(?P<username>.+?)[\s\r\n]+PASS(?:WORD)?:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
        )
        
        # System info patterns
        self.system_info_patterns = PatternGroup("system_info")
        
        # OS version
        self.system_info_patterns.add_pattern(
            FlexiblePattern("os_version", priority=5)
            .add_regex(r"OS(?:\s+VERSION)?:[\s]*(?P<os>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"OPERATING\s+SYSTEM:[\s]*(?P<os>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "os"])
            .add_json_path(["OS"])
        )
        
        # PC/Computer name
        self.system_info_patterns.add_pattern(
            FlexiblePattern("computer_name", priority=5)
            .add_regex(r"(?:PC|COMPUTER)[\s-]*NAME:[\s]*(?P<computer_name>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"HOSTNAME:[\s]*(?P<computer_name>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "computerName"])
            .add_json_path(["system", "ComputerName"])
            .add_json_path(["ComputerName"])
        )
        
        # Username
        self.system_info_patterns.add_pattern(
            FlexiblePattern("username", priority=5)
            .add_regex(r"USER(?:NAME)?:[\s]*(?P<username>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"LOGIN\s+NAME:[\s]*(?P<username>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "username"])
            .add_json_path(["system", "UserName"])
            .add_json_path(["UserName"])
        )
        
        # IP address (local and public)
        self.system_info_patterns.add_pattern(
            FlexiblePattern("ip_address", priority=5)
            .add_regex(r"IP(?:[\s-]*ADDRESS)?:[\s]*(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"(?:PUBLIC|EXTERNAL)[\s-]*IP:[\s]*(?P<public_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"(?:LOCAL|INTERNAL)[\s-]*IP:[\s]*(?P<local_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "ip"])
            .add_json_path(["IP"])
        )
        
        # Country
        self.system_info_patterns.add_pattern(
            FlexiblePattern("country", priority=4)
            .add_regex(r"COUNTRY:[\s]*(?P<country>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "country"])
            .add_json_path(["Country"])
        )
        
        # Antivirus
        self.system_info_patterns.add_pattern(
            FlexiblePattern("antivirus", priority=4)
            .add_regex(r"(?:ANTIVIRUS|AV|SECURITY)[\s:]*(?P<antivirus>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "antivirus"])
            .add_json_path(["Antivirus"])
        )
        
        # Screen resolution
        self.system_info_patterns.add_pattern(
            FlexiblePattern("resolution", priority=3)
            .add_regex(r"(?:RESOLUTION|SCREEN)[\s:]*(?P<resolution>\d+\s*[xX]\s*\d+)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["system", "resolution"])
            .add_json_path(["Resolution"])
        )
        
        # Credit card patterns
        self.credit_card_patterns = PatternGroup("credit_cards")
        
        # Standard credit card format
        self.credit_card_patterns.add_pattern(
            FlexiblePattern("card_standard", priority=8)
            .add_regex(r"CARD[\s-]*NUMBER:[\s]*(?P<number>(?:\d{4}[\s-]*){3}\d{4})[\s\r\n]+EXP(?:IRY)?[\s-]*(?:DATE)?:[\s]*(?P<expiry>\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(?P<cvv>\d{3,4})(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"(?:CC|CARD)[\s-]*#:[\s]*(?P<number>(?:\d{4}[\s-]*){3}\d{4})[\s\r\n]+EXP(?:IRY)?:[\s]*(?P<expiry>\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(?P<cvv>\d{3,4})(?:[\r\n]|$)", re.IGNORECASE)
        )
        
        # With cardholder
        self.credit_card_patterns.add_pattern(
            FlexiblePattern("card_with_holder", priority=9)
            .add_regex(r"CARD[\s-]*NUMBER:[\s]*(?P<number>(?:\d{4}[\s-]*){3}\d{4})[\s\r\n]+EXP(?:IRY)?[\s-]*(?:DATE)?:[\s]*(?P<expiry>\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(?P<cvv>\d{3,4})[\s\r\n]+(?:CARD)?[\s-]*HOLDER:[\s]*(?P<holder>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"(?:CC|CARD)[\s-]*#:[\s]*(?P<number>(?:\d{4}[\s-]*){3}\d{4})[\s\r\n]+EXP(?:IRY)?:[\s]*(?P<expiry>\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(?P<cvv>\d{3,4})[\s\r\n]+NAME:[\s]*(?P<holder>.+?)(?:[\r\n]|$)", re.IGNORECASE)
        )
        
        # Simplified format
        self.credit_card_patterns.add_pattern(
            FlexiblePattern("card_simplified", priority=7)
            .add_regex(r"CARD:[\s]*(?P<number>(?:\d{4}[\s-]*){3}\d{4})[\s\r\n]+EXP:[\s]*(?P<expiry>\d{2}\/\d{2,4})[\s\r\n]+CVV:[\s]*(?P<cvv>\d{3,4})(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"CC:[\s]*(?P<number>(?:\d{4}[\s-]*){3}\d{4})[\s\r\n]+EXP:[\s]*(?P<expiry>\d{2}\/\d{2,4})[\s\r\n]+(?:CVC|CVV):[\s]*(?P<cvv>\d{3,4})(?:[\r\n]|$)", re.IGNORECASE)
        )
        
        # Json format
        self.credit_card_patterns.add_pattern(
            FlexiblePattern("card_json", priority=6)
            .add_json_path(["cards"])
            .add_json_path(["creditCards"])
            .add_json_path(["CreditCards"])
        )
        
        # Crypto wallet patterns
        self.crypto_patterns = PatternGroup("crypto_wallets")
        
        # Bitcoin wallets
        self.crypto_patterns.add_pattern(
            FlexiblePattern("bitcoin_wallet", priority=7)
            .add_regex(r"BITCOIN(?:[\\s-]*WALLET)?:[\\s]*(?P<bitcoin_value>.+?)(?:[\\r\\n]|$)", re.IGNORECASE)
            .add_regex(r"BTC[\\s-]*(?:WALLET|ADDRESS)?:[\\s]*(?P<bitcoin_value>.+?)(?:[\\r\\n]|$)", re.IGNORECASE)
            .add_json_path(["wallets", "bitcoin"])
            .add_json_path(["Bitcoin"])
        )
        
        # Ethereum wallets
        self.crypto_patterns.add_pattern(
            FlexiblePattern("ethereum_wallet", priority=7)
            .add_regex(r"ETHEREUM(?:[\\s-]*WALLET)?:[\\s]*(?P<ethereum_value>.+?)(?:[\\r\\n]|$)", re.IGNORECASE)
            .add_regex(r"ETH[\\s-]*(?:WALLET|ADDRESS)?:[\\s]*(?P<ethereum_value>.+?)(?:[\\r\\n]|$)", re.IGNORECASE)
            .add_json_path(["wallets", "ethereum"])
            .add_json_path(["Ethereum"])
        )
        
        # Generic wallet or seed phrase
        self.crypto_patterns.add_pattern(
            FlexiblePattern("generic_wallet", priority=6)
            .add_regex(r"(?:CRYPTO)?[\\s-]*WALLET(?:[\\s-]*SEED)?:[\\s]*(?P<generic_value>.+?)(?:[\\r\\n]|$)", re.IGNORECASE)
            .add_regex(r"SEED[\\s-]*PHRASE:[\\s]*(?P<seed_phrase>.+?)(?:[\\r\\n]|$)", re.IGNORECASE)
            .add_json_path(["wallets"])
            .add_json_path(["Wallets"])
        )
        
        # Cookie patterns
        self.cookie_patterns = PatternGroup("cookies")

    def can_parse(self, message_data: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Determine if this plugin can parse the given message.
        
        Args:
            message_data: Message data including text and attachments
            
        Returns:
            Tuple of (can_parse, confidence_score)
        """
        text = message_data.get("text", "")
        if not text:
            return False, 0.0
            
        # Check for Azorult headers
        header_matches = self.header_patterns.match(text)
        if header_matches:
            return True, 0.9
            
        # Check for section markers
        section_matches = self.section_patterns.match(text)
        if len(section_matches) >= 2:  # Multiple sections suggest Azorult format
            return True, 0.8
            
        # Look for characteristic patterns
        credential_matches = self.credential_patterns.match(text)
        system_matches = self.system_info_patterns.match(text)
        card_matches = self.credit_card_patterns.match(text)
        
        # Calculate confidence based on pattern matches
        confidence = 0.0
        if credential_matches and system_matches:
            confidence += 0.4
        if card_matches:  # Azorult often includes credit card data
            confidence += 0.3
            
        return confidence >= self.confidence_threshold, confidence
        
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse the message and extract structured data.
        
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
            "file_paths": [],
            "parsing_errors": []
        }
        
        text = message_data.get("text", "")
        if not text:
            return result
            
        try:
            # Extract credentials
            credential_matches = self.credential_patterns.match(text)
            urls = credential_matches.get('url', [])
            domains = credential_matches.get('domain', [])
            usernames = credential_matches.get('username', [])
            passwords = credential_matches.get('password', [])
            softwares = credential_matches.get('software', [])
            hosts = credential_matches.get('host', [])

            # Determine the number of potential credential sets
            num_creds = 0
            if usernames: num_creds = len(usernames)
            if passwords and len(passwords) > num_creds: num_creds = len(passwords)
            # Expand based on other primary fields if necessary
            if urls and len(urls) > num_creds: num_creds = len(urls)
            if domains and len(domains) > num_creds: num_creds = len(domains)
            if hosts and len(hosts) > num_creds: num_creds = len(hosts)
            if softwares and len(softwares) > num_creds: num_creds = len(softwares)

            for i in range(num_creds):
                username = usernames[i] if i < len(usernames) else None
                password = passwords[i] if i < len(passwords) else None

                # Skip if essential parts are missing
                if not username or not password:
                    continue

                url = urls[i] if i < len(urls) else None
                domain_match = domains[i] if i < len(domains) else None
                host = hosts[i] if i < len(hosts) else None
                software = softwares[i] if i < len(softwares) else None

                # Determine domain logic
                final_domain = None
                if url:
                    final_domain = self.extract_domain_from_url(url)
                elif domain_match:
                    final_domain = domain_match
                elif host: # Added check for FTP host
                     final_domain = host
                elif username: # Fallback to extracting from username/email
                    final_domain = self.extract_domain_from_username(username)

                result["credentials"].append({
                    "url": url,
                    "domain": final_domain,
                    "username": username,
                    "password": password,
                    "software": software
                })

            # Extract system info
            system_matches = self.system_info_patterns.match(text)
            for key, values in system_matches.items():
                if values: # If the pattern found anything for this key
                    # Take the first match found for this system info key
                    # Handle potential list values if multiple regexes match the same key name
                    if isinstance(values[0], list):
                         # If value is a list (e.g. unnamed groups), join or take first? Take first for now.
                         result["system_info"][key] = values[0][0] if values[0] else None
                    else:
                         result["system_info"][key] = values[0]

            # Extract credit cards
            card_matches = self.credit_card_patterns.match(text)
            numbers = card_matches.get('number', [])
            expiries = card_matches.get('expiry', [])
            cvvs = card_matches.get('cvv', [])
            holders = card_matches.get('holder', [])

            num_cards = 0
            if numbers: num_cards = len(numbers)
            if expiries and len(expiries) > num_cards: num_cards = len(expiries)
            if cvvs and len(cvvs) > num_cards: num_cards = len(cvvs)

            for i in range(num_cards):
                number = numbers[i] if i < len(numbers) else None
                expiry = expiries[i] if i < len(expiries) else None
                cvv = cvvs[i] if i < len(cvvs) else None

                # Basic validation: need number, expiry, cvv
                if not number or not expiry or not cvv:
                    continue

                result["credit_cards"].append({
                    "number": number.replace(" ", "").replace("-", ""), # Keep cleaning
                    "expiry": expiry,
                    "cvv": cvv,
                    "holder": holders[i] if i < len(holders) else None # Holder is optional
                })

            # Extract crypto wallets
            crypto_matches = self.crypto_patterns.match(text)

            # Process Bitcoin
            btc_values = crypto_matches.get('bitcoin_value', [])
            for value in btc_values:
                result["crypto_wallets"].append({"type": "bitcoin", "value": value})

            # Process Ethereum
            eth_values = crypto_matches.get('ethereum_value', [])
            for value in eth_values:
                result["crypto_wallets"].append({"type": "ethereum", "value": value})

            # Process Generic Wallets
            gen_values = crypto_matches.get('generic_value', [])
            for value in gen_values:
                result["crypto_wallets"].append({"type": "generic", "value": value})

            # Process Seed Phrases
            seed_phrases = crypto_matches.get('seed_phrase', [])
            for phrase in seed_phrases:
                # Use 'seed_phrase' as type for clarity
                result["crypto_wallets"].append({"type": "seed_phrase", "value": phrase})

            # TODO: Add Cookie extraction using self.cookie_patterns.match(text)
            # cookie_matches = self.cookie_patterns.match(text) ... process results ...

            # Calculate value score
            result["value_score"] = self.calculate_value_score(result)

        except Exception as e:
            error_msg = f"Error parsing Azorult data: {str(e)}"
            logger.error(error_msg, exc_info=True)
            result["parsing_errors"].append(error_msg)
            
        return result