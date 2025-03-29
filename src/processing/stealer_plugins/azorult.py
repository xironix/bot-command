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
            .add_validation(validate_credentials)
        )
        
        # SOFTWARE / USER / PASS format (for desktop applications)
        self.credential_patterns.add_pattern(
            FlexiblePattern("software_user_pass", priority=4)
            .add_regex(r"SOFTWARE:[\s]*(?P<software>.+?)[\s\r\n]+USER:[\s]*(?P<username>.+?)[\s\r\n]+PASS:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"APPLICATION:[\s]*(?P<software>.+?)[\s\r\n]+USERNAME:[\s]*(?P<username>.+?)[\s\r\n]+PASSWORD:[\s]*(?P<password>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_validation(validate_credentials)
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
            .add_regex(r"BITCOIN(?:[\s-]*WALLET)?:[\s]*(?P<value>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"BTC[\s-]*(?:WALLET|ADDRESS)?:[\s]*(?P<value>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["wallets", "bitcoin"])
            .add_json_path(["Bitcoin"])
        )
        
        # Ethereum wallets
        self.crypto_patterns.add_pattern(
            FlexiblePattern("ethereum_wallet", priority=7)
            .add_regex(r"ETHEREUM(?:[\s-]*WALLET)?:[\s]*(?P<value>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"ETH[\s-]*(?:WALLET|ADDRESS)?:[\s]*(?P<value>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["wallets", "ethereum"])
            .add_json_path(["Ethereum"])
        )
        
        # Generic wallet or seed phrase
        self.crypto_patterns.add_pattern(
            FlexiblePattern("generic_wallet", priority=6)
            .add_regex(r"(?:CRYPTO)?[\s-]*WALLET(?:[\s-]*SEED)?:[\s]*(?P<value>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_regex(r"SEED[\s-]*PHRASE:[\s]*(?P<seed_phrase>.+?)(?:[\r\n]|$)", re.IGNORECASE)
            .add_json_path(["wallets"])
            .add_json_path(["Wallets"])
        )
        
        # Cookie patterns
        self.cookie_patterns = Pat