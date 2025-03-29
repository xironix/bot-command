"""
Base class for stealer parser plugins.

This module defines the base class that all stealer parser plugins must inherit from.
"""

import base64
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import logging

class StealerParserPlugin(ABC):
    """Base class for all stealer parser plugins."""
    
    def __init__(self):
        self.name = "base_plugin"
        self.confidence_threshold = 0.7
        self.value_multiplier = 1.0  # Value multiplier for this stealer type
        self.logger = logging.getLogger(f"stealer_parser.{self.name}")
        self.debug_mode = False  # Debug mode flag
        self.debug_data = {}  # Temporary storage for debug data
        
    @abstractmethod
    def can_parse(self, message_data: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Determine if this plugin can parse the given message.
        
        Args:
            message_data: Message data including text and attachments
            
        Returns:
            Tuple of (can_parse, confidence_score)
        """
        pass
    
    @abstractmethod
    def parse(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse the message and extract structured data.
        
        Args:
            message_data: Message data including text and attachments
            
        Returns:
            Dictionary with extracted structured data containing:
                - credentials: List of credential dictionaries
                - cookies: List of cookie dictionaries
                - system_info: Dictionary with system information
                - crypto_wallets: List of cryptocurrency wallet data
                - file_paths: List of discovered/important file paths
                - value_score: Optional value score for this data
                - parsing_errors: List of parsing errors
        """
        pass

    def enable_debug(self):
        """Enable debug mode for this parser."""
        self.debug_mode = True
        self.debug_data = {
            "fingerprinting": [],
            "pattern_matches": {},
            "extraction_details": {},
            "value_calculation": {}
        }
        self.logger.debug(f"Debug mode enabled for {self.name}")
        
    def disable_debug(self):
        """Disable debug mode for this parser."""
        self.debug_mode = False
        self.debug_data = {}
        self.logger.debug(f"Debug mode disabled for {self.name}")
        
    def get_debug_data(self) -> Dict[str, Any]:
        """
        Get accumulated debug data.
        
        Returns:
            Dictionary with debug data or empty dict if debug mode is disabled
        """
        if not self.debug_mode:
            return {}
            
        return self.debug_data
        
    def extract_domain_from_url(self, url: str) -> Optional[str]:
        """
        Extract domain from URL.
        
        Args:
            url: URL string
            
        Returns:
            Domain string or None
        """
        if not url:
            return None
            
        # Add protocol if missing
        if '://' not in url:
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except Exception:
            return None
            
    def extract_domain_from_username(self, username: str) -> Optional[str]:
        """
        Extract domain from a username if it's an email.
        
        Args:
            username: Username string
            
        Returns:
            Domain string or None
        """
        # Check if it's an email
        if username and '@' in username:
            return username.split('@')[1]
        return None
        
    def decode_base64(self, data: str) -> str:
        """
        Safely decode Base64 data.
        
        Args:
            data: Base64 encoded string
            
        Returns:
            Decoded string, or original if decoding fails
        """
        try:
            # Try standard Base64 decoding
            return base64.b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            try:
                # Try URL-safe Base64 decoding
                return base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
            except Exception:
                # Return original if both fail
                return data
                
    def parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a file for stealer data.
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with extracted structured data
        """
        # Child classes should override this method for stealer-specific file parsing
        return {
            "credentials": [],
            "cookies": [],
            "system_info": {},
            "crypto_wallets": [],
            "file_paths": [],
            "parsing_errors": []
        }
        
    def calculate_value_score(self, parsed_data: Dict[str, Any]) -> float:
        """
        Calculate value score for parsed data.
        
        Args:
            parsed_data: Dictionary with parsed data
            
        Returns:
            Value score (0-100)
        """
        # Base value calculation, child classes can override or enhance this
        score = 0
        
        # Value from credentials
        for cred in parsed_data.get("credentials", []):
            # Base score for any credential
            cred_score = 5
            
            # Domain-based scoring
            domain = cred.get("domain", "").lower()
            if domain:
                # Financial services (highest value)
                if any(term in domain for term in ["bank", "chase", "wellsfargo", "paypal", "coinbase", 
                                                  "binance", "visa", "mastercard", "amex", "coinbase"]):
                    cred_score += 30
                # Enterprise services (high value)
                elif any(term in domain for term in ["office365", "salesforce", "aws", "azure", 
                                                    "oracle", "sap", "workday", "atlassian"]):
                    cred_score += 25
                # Email providers (medium value)
                elif any(term in domain for term in ["gmail", "outlook", "yahoo", "protonmail"]):
                    cred_score += 15
                # Social media (lower value)
                elif any(term in domain for term in ["facebook", "twitter", "instagram", "tiktok"]):
                    cred_score += 10
                # Any other domains
                else:
                    cred_score += 5
                    
            # Username-based scoring
            username = cred.get("username", "").lower()
            if username:
                # Admin or privileged accounts
                if any(term in username for term in ["admin", "root", "superuser", "sysadmin"]):
                    cred_score += 15
                # Financial accounts
                elif any(term in username for term in ["finance", "account", "payment", "billing"]):
                    cred_score += 10
                # Corporate emails (not public providers)
                elif '@' in username and not any(term in username for term in ["@gmail", "@yahoo", "@hotmail", "@outlook"]):
                    cred_score += 5
                    
            score += cred_score
            
        # Value from crypto wallets (highest value)
        for wallet in parsed_data.get("crypto_wallets", []):
            wallet_score = 25  # Base score for any wallet
            wallet_type = wallet.get("type", "").lower()
            
            # Different types have different values
            if wallet_type == "btc" or wallet_type == "bitcoin":
                wallet_score += 15
            elif wallet_type == "eth" or wallet_type == "ethereum":
                wallet_score += 10
            else:
                wallet_score += 5
                
            # Private keys are more valuable than just addresses
            if wallet.get("private_key"):
                wallet_score += 20
            elif wallet.get("seed_phrase") or wallet.get("mnemonic"):
                wallet_score += 25
                
            score += wallet_score
            
        # Value from system info
        system_info = parsed_data.get("system_info", {})
        if system_info:
            # Look for enterprise systems
            os_info = system_info.get("os", "").lower()
            if "enterprise" in os_info or "server" in os_info:
                score += 10
                
            # Corporate network indicators
            if system_info.get("is_corporate", False):
                score += 15
                
        # Adjust final score with stealer-specific multiplier
        final_score = score * self.value_multiplier
        
        # Cap at 100
        return min(final_score, 100)
