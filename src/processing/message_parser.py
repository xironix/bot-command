"""
Message parser for intercepted stealer bot messages.

This module parses different types of data from intercepted Telegram bot messages,
including credentials, cookies, system information, and more.
"""

import json
import logging
import os
import re
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger(__name__)

class MessageParser:
    """Parser for intercepted stealer bot messages."""
    
    def __init__(self):
        """Initialize message parser."""
        # Load parser configuration and fallback patterns
        self._load_patterns()
        
        # Initialize parser plugins
        self._initialize_plugins()
        
        # Track parsing statistics
        self.stats = {
            "total_processed": 0,
            "successful_credential_extractions": 0,
            "successful_cookie_extractions": 0,
            "successful_system_info_extractions": 0,
            "successful_crypto_wallet_extractions": 0,
            "high_value_extractions": 0,  # Count of high-value logs (>70 score)
            "plugin_successes": 0,        # Count of successful plugin parses
            "plugin_failures": 0,         # Count of plugin failures
            "failed_parsings": 0,
            "plugins": {}                 # Plugin-specific stats
        }
        
        # Initialize plugin stats
        for plugin in self.plugins:
            self.stats["plugins"][plugin.name] = {
                "attempts": 0,
                "successes": 0,
                "failures": 0,
                "avg_confidence": 0.0,
                "avg_value_score": 0.0
            }
            
        # Debug options
        self.debug_mode = False
        self.debug_output_dir = "debug_logs"
        self.current_debug_data = {}
    
    def _load_patterns(self):
        """Load parsing patterns with multiple fallback options."""
        # Credential patterns with various formats seen in the wild
        self._credential_patterns = [
            # Email/password combinations
            re.compile(r"(?:login|email|username|user|account)[\s:]+([^\s@]+@[^\s@]+\.[^\s@]+)[\s\r\n]+(?:password|pwd|pass|passwd)[\s:]+([^\s\r\n]+)", re.IGNORECASE),
            # Generic username/password combinations
            re.compile(r"(?:username|user|login|account)[\s:]+([^\s\r\n]{3,})[\s\r\n]+(?:password|pwd|pass|passwd)[\s:]+([^\s\r\n]+)", re.IGNORECASE),
            # Domain-specific credentials
            re.compile(r"(?:site|domain|service|url|website)[\s:]+([^\s\r\n]+)[\s\r\n]+(?:username|user|login|email|account)[\s:]+([^\s\r\n]+)[\s\r\n]+(?:password|pwd|pass|passwd)[\s:]+([^\s\r\n]+)", re.IGNORECASE),
            # Alternative format with title/header
            re.compile(r"(?:credentials|account|login info)[\s\r\n]+(?:site|domain|service|url|website)[\s:]+([^\s\r\n]+)[\s\r\n]+(?:username|user|login|email)[\s:]+([^\s\r\n]+)[\s\r\n]+(?:password|pwd|pass)[\s:]+([^\s\r\n]+)", re.IGNORECASE),
            # Key-value pairs format
            re.compile(r"username:\s*([^\r\n]+)[\r\n]+password:\s*([^\r\n]+)", re.IGNORECASE),
            # URL with credentials embedded
            re.compile(r"(?:url|link)[\s:]+(?:https?://)?(?:www\.)?([^/\s]+)(?:[^\r\n]*)[\r\n]+(?:username|user|login|email)[\s:]+([^\s\r\n]+)[\s\r\n]+(?:password|pwd|pass)[\s:]+([^\s\r\n]+)", re.IGNORECASE),
        ]
        
        # Cookie patterns
        self._cookie_patterns = [
            # Standard cookie format
            re.compile(r"(?:cookie|cookies)[\s:]+(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
            # Domain-specific cookies
            re.compile(r"domain[\s:]+([^\s\r\n]+)[\s\r\n]+(?:cookie|cookies)[\s:]+(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
            # Cookie with name/value pairs
            re.compile(r"(?:cookie|cookies)[\s:]+([^=\s]+)=([^;\s]+)", re.IGNORECASE),
            # Browser cookie format
            re.compile(r"(?:browser|chrome|firefox|edge|safari)[\s:]+(?:cookie|cookies)[\s:]+(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
        ]
        
        # System info patterns
        self._system_info_patterns = [
            # OS and version
            re.compile(r"(?:os|operating system|system)[\s:]+([^\s\r\n][^\r\n]+)", re.IGNORECASE),
            # Hardware info
            re.compile(r"(?:hardware|pc|computer|device|machine|system)[\s:]+([^\s\r\n][^\r\n]+)", re.IGNORECASE),
            # IP addresses (IPv4 and IPv6)
            re.compile(r"(?:ip|address|ipv4)[\s:]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
            re.compile(r"(?:ipv6|ip)[\s:]+([0-9a-fA-F:]+)", re.IGNORECASE),
            # Full system info blocks
            re.compile(r"(?:system info|sysinfo|system information|pc info|computer info|device info)[\s:]+(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
            # Windows version specific
            re.compile(r"(?:windows|win)[\s:]+([^\s\r\n][^\r\n]+)", re.IGNORECASE),
            # MAC address
            re.compile(r"(?:mac address|mac|physical address)[\s:]+([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", re.IGNORECASE),
            # Username/hostname format
            re.compile(r"(?:username|user|hostname|computer name)[\s:]+([^\s\r\n][^\r\n]+)", re.IGNORECASE),
        ]
        
    def _initialize_plugins(self):
        """Initialize parser plugins for different bot types."""
        # Import and initialize stealer-specific parser plugins
        from src.processing.stealer_plugins import AVAILABLE_PLUGINS
        self.plugins = AVAILABLE_PLUGINS
        logger.info(f"Initialized {len(self.plugins)} stealer parser plugins")
        
    def parse_message(self, message_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a message and extract structured data.
        
        Args:
            message_data: Raw message data
            
        Returns:
            Dictionary with extracted structured data
        """
        self.stats["total_processed"] += 1
        
result = {
            "raw_data": message_data,
            "timestamp": datetime.utcnow(),
            "bot_id": message_data.get("bot_id"),
            "bot_username": message_data.get("bot_username"),
            "message_id": message_data.get("message_id"),
            "credentials": [],
            "cookies": [],
            "system_info": {},
            "crypto_wallets": [],  # Added for crypto wallet data
            "file_paths": [],
            "value_score": 0,      # Added for value scoring
            "parsing_errors": []
        }
        
        # Extract text content
        text = message_data.get("text", "")
        
        try:
            # Try plugin-based parsing first (for known bot types)
            if self.plugins:
                # Initialize debug data for this message
                if self.debug_mode:
                    self.current_debug_data = {
                        "message_id": message_data.get("message_id", "unknown"),
                        "bot_id": message_data.get("bot_id", "unknown"),
                        "bot_username": message_data.get("bot_username", "unknown"),
                        "timestamp": datetime.utcnow().isoformat(),
                        "text_length": len(message_data.get("text", "")),
                        "has_media": message_data.get("has_media", False),
                        "media_path": message_data.get("media_path", None),
                        "plugin_detection": {},
                        "selected_plugin": None,
                        "extraction_details": {},
                        "fallback_patterns": [],
                        "errors": []
                    }
                
                # Try to find a matching plugin
                best_plugin = None
                best_confidence = 0.0
                
                for plugin in self.plugins:
                    # Record attempt statistics
                    self.stats["plugins"][plugin.name]["attempts"] += 1
                    
                    can_parse, confidence = plugin.can_parse(message_data)
                    
                    # Record plugin detection attempt in debug data
                    if self.debug_mode:
                        self.current_debug_data["plugin_detection"][plugin.name] = {
                            "can_parse": can_parse,
                            "confidence": confidence,
                            "threshold": plugin.confidence_threshold
                        }
                    
                    if can_parse and confidence > best_confidence:
                        best_plugin = plugin
                        best_confidence = confidence
                        
                # If we found a suitable plugin, use it
                if best_plugin and best_confidence >= best_plugin.confidence_threshold:
                    try:
                        logger.info(f"Using {best_plugin.name} to parse message (confidence: {best_confidence:.2f})")
                        plugin_result = best_plugin.parse(message_data)
                        
                        # Merge plugin results into our result structure
                        for key in ["credentials", "cookies", "file_paths"]:
                            if key in plugin_result and plugin_result[key]:
                                result[key] = plugin_result[key]
                                if key == "credentials":
                                    self.stats["successful_credential_extractions"] += 1
                                elif key == "cookies":
                                    self.stats["successful_cookie_extractions"] += 1
                                    
                        # Merge system info if present
                        if "system_info" in plugin_result and plugin_result["system_info"]:
                            result["system_info"] = plugin_result["system_info"]
                            self.stats["successful_system_info_extractions"] += 1
                            
                        # Add any crypto wallet data
                        if "crypto_wallets" in plugin_result and plugin_result["crypto_wallets"]:
                            result["crypto_wallets"] = plugin_result["crypto_wallets"]
                            
                        # Add any parsing errors
                        if "parsing_errors" in plugin_result and plugin_result["parsing_errors"]:
                            result["parsing_errors"].extend(plugin_result["parsing_errors"])
                            
                        # Add value score if available
                        if "value_score" in plugin_result:
                            result["value_score"] = plugin_result["value_score"]
                            
                        # Record plugin success statistics
                        self.stats["plugin_successes"] += 1
                        self.stats["plugins"][best_plugin.name]["successes"] += 1
                        self.stats["plugins"][best_plugin.name]["avg_confidence"] = (
                            (self.stats["plugins"][best_plugin.name]["avg_confidence"] * 
                             (self.stats["plugins"][best_plugin.name]["attempts"] - 1) + 
                             best_confidence) / self.stats["plugins"][best_plugin.name]["attempts"]
                        )
                        
                        if "value_score" in plugin_result:
                            self.stats["plugins"][best_plugin.name]["avg_value_score"] = (
                                (self.stats["plugins"][best_plugin.name]["avg_value_score"] * 
                                 (self.stats["plugins"][best_plugin.name]["successes"] - 1) + 
                                 plugin_result["value_score"]) / self.stats["plugins"][best_plugin.name]["successes"]
                            )
                            
                            # Track high-value extractions
                            if plugin_result["value_score"] > 70:
                                self.stats["high_value_extractions"] += 1
                                
                        # Record selected plugin in debug data
                        if self.debug_mode:
                            self.current_debug_data["selected_plugin"] = best_plugin.name
                            self.current_debug_data["extraction_details"] = best_plugin.get_debug_data()
                            
                            # Save debug data to file
                            self._save_debug_data(
                                message_data.get("message_id", "unknown"),
                                self.current_debug_data
                            )
                        
                        # Skip generic parsing if a plugin succeeded
                        return result
                    except Exception as e:
                        error_msg = f"Plugin {best_plugin.name} failed: {str(e)}"
                        logger.error(error_msg, exc_info=True)
                        result["parsing_errors"].append(error_msg)
                        
                        # Record error in debug data
                        if self.debug_mode:
                            self.current_debug_data["errors"].append({
                                "plugin": best_plugin.name,
                                "error": str(e),
                                "traceback": traceback.format_exc()
                            })
                        
                        # Record plugin failure statistics
                        self.stats["plugin_failures"] += 1
                        self.stats["plugins"][best_plugin.name]["failures"] += 1
                        
                        # Continue with generic parsing as fallback
                
            # Apply generic regex parsing as fallback
            if self.debug_mode:
                self.current_debug_data["fallback_reason"] = "No matching plugin or plugin failure"
            
            # Extract credentials
            credentials = self._extract_credentials(text)
            if credentials:
                result["credentials"] = credentials
                self.stats["successful_credential_extractions"] += 1
                
                # Debug info for credential extraction
                if self.debug_mode:
                    self.current_debug_data["fallback_patterns"].append({
                        "type": "credentials",
                        "count": len(credentials),
                        "details": credentials[:5]  # First 5 credentials for debugging
                    })
                
            # Extract cookies
            cookies = self._extract_cookies(text)
            if cookies:
                result["cookies"] = cookies
                self.stats["successful_cookie_extractions"] += 1
                
                # Debug info for cookie extraction
                if self.debug_mode:
                    self.current_debug_data["fallback_patterns"].append({
                        "type": "cookies",
                        "count": len(cookies),
                        "details": cookies[:5]  # First 5 cookies for debugging
                    })
                
            # Extract system info
            system_info = self._extract_system_info(text)
            if system_info:
                result["system_info"] = system_info
                self.stats["successful_system_info_extractions"] += 1
                
                # Debug info for system info extraction
                if self.debug_mode:
                    self.current_debug_data["fallback_patterns"].append({
                        "type": "system_info",
                        "details": system_info
                    })
                
            # Track crypto wallet extractions when found
            if result.get("crypto_wallets"):
                self.stats["successful_crypto_wallet_extractions"] += 1
                
            # Check for media files
            if message_data.get("has_media") and message_data.get("media_path"):
                result["file_paths"].append(message_data["media_path"])
                
                # If it's a known file type, try to parse it
                if self._is_parsable_file(message_data["media_path"]):
                    try:
                        parsed_file_data = self._parse_file(message_data["media_path"])
                        
                        # Merge parsed data with existing results
                        for key in ["credentials", "cookies", "system_info"]:
                            if key in parsed_file_data and parsed_file_data[key]:
                                if isinstance(parsed_file_data[key], list):
                                    result[key].extend(parsed_file_data[key])
                                elif isinstance(parsed_file_data[key], dict) and result[key]:
                                    result[key].update(parsed_file_data[key])
                                else:
                                    result[key] = parsed_file_data[key]
                    except Exception as e:
                        error_msg = f"Failed to parse file {message_data['media_path']}: {str(e)}"
                        logger.error(error_msg)
                        result["parsing_errors"].append(error_msg)
        except Exception as e:
            error_msg = f"Error during message parsing: {str(e)}"
            logger.error(error_msg, exc_info=True)
            result["parsing_errors"].append(error_msg)
            self.stats["failed_parsings"] += 1
        
        return result
        
    def _extract_credentials(self, text: str) -> List[Dict[str, str]]:
        """
        Extract credentials from text.
        
        Args:
            text: Message text
            
        Returns:
            List of credential dictionaries
        """
        credentials = []
        pattern_matches = {}  # For debug purposes
        
        # Try each pattern
        for i, pattern in enumerate(self._credential_patterns):
            pattern_key = f"credential_pattern_{i}"
            pattern_matches[pattern_key] = 0
            
            matches = pattern.finditer(text)
            for match in matches:
                pattern_matches[pattern_key] += 1
                if len(match.groups()) == 2:
                    # Username/password format
                    credentials.append({
                        "username": match.group(1),
                        "password": match.group(2),
                        "domain": self._extract_domain_from_username(match.group(1))
                    })
                elif len(match.groups()) == 3:
                    # Domain/username/password format
                    credentials.append({
                        "domain": match.group(1),
                        "username": match.group(2),
                        "password": match.group(3)
                    })
        
        return credentials
        
    def _extract_domain_from_username(self, username: str) -> Optional[str]:
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
        
    def _extract_cookies(self, text: str) -> List[Dict[str, str]]:
        """
        Extract cookies from text.
        
        Args:
            text: Message text
            
        Returns:
            List of cookie dictionaries
        """
        cookies = []
        
        # Try each pattern
        for pattern in self._cookie_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                if len(match.groups()) == 1:
                    # Generic cookie format
                    cookies.append({
                        "value": match.group(1).strip()
                    })
                elif len(match.groups()) == 2:
                    # Domain-specific cookie format
                    cookies.append({
                        "domain": match.group(1).strip(),
                        "value": match.group(2).strip()
                    })
                    
        return cookies
        
    def _extract_system_info(self, text: str) -> Dict[str, str]:
        """
        Extract system information from text.
        
        Args:
            text: Message text
            
        Returns:
            Dictionary with system information
        """
        system_info = {}
        
        # Try each pattern
        for pattern in self._system_info_patterns:
            matches = pattern.finditer(text)
            for match in matches:
                if pattern.pattern.startswith("(?:os|operating"):
                    system_info["os"] = match.group(1).strip()
                elif pattern.pattern.startswith("(?:hardware|pc|computer"):
                    system_info["hardware"] = match.group(1).strip()
                elif pattern.pattern.startswith("(?:ip|address"):
                    system_info["ip"] = match.group(1).strip()
                elif pattern.pattern.startswith("(?:system info|sysinfo"):
                    system_info["full_info"] = match.group(1).strip()
                    
        return system_info
        
    def enable_debug(self, output_dir: Optional[str] = None):
        """
        Enable debug mode for detailed logging.
        
        Args:
            output_dir: Optional custom directory for debug output
        """
        self.debug_mode = True
        
        if output_dir:
            self.debug_output_dir = output_dir
            
        # Create debug output directory if it doesn't exist
        os.makedirs(self.debug_output_dir, exist_ok=True)
        
        # Enable debug on all plugins
        for plugin in self.plugins:
            plugin.enable_debug()
            
        logger.info(f"Debug mode enabled, output will be saved to {self.debug_output_dir}")
        
    def disable_debug(self):
        """Disable debug mode."""
        self.debug_mode = False
        
        # Disable debug on all plugins
        for plugin in self.plugins:
            plugin.disable_debug()
            
        logger.info("Debug mode disabled")
        
    def _save_debug_data(self, message_id: str, debug_data: Dict[str, Any]):
        """
        Save debug data to a file.
        
        Args:
            message_id: Message ID or other identifier
            debug_data: Debug data to save
        """
        if not self.debug_mode:
            return
            
        try:
            # Create filename based on timestamp and message ID
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{message_id}.json"
            file_path = os.path.join(self.debug_output_dir, filename)
            
            # Save debug data as JSON
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(debug_data, f, indent=2, default=str)
                
            logger.debug(f"Debug data saved to {file_path}")
        except Exception as e:
            logger.error(f"Failed to save debug data: {str(e)}")
            
    def get_parser_stats(self) -> Dict[str, Any]:
        """
        Get statistics on parser performance.
        
        Returns:
            Dictionary with parser statistics including plugin performance
        """
        stats = dict(self.stats)  # Make a copy
        
        # Add success rate calculations
        if stats["total_processed"] > 0:
            stats["overall_success_rate"] = (
                (stats["total_processed"] - stats["failed_parsings"]) / 
                stats["total_processed"] * 100
            )
            
            # Calculate plugin success rates
            for plugin_name, plugin_stats in stats["plugins"].items():
                if plugin_stats["attempts"] > 0:
                    plugin_stats["success_rate"] = (
                        plugin_stats["successes"] / plugin_stats["attempts"] * 100
                    )
                    
            # Calculate overall plugin usage rate
            stats["plugin_usage_rate"] = (
                stats["plugin_successes"] / stats["total_processed"] * 100
            )
            
        return stats
    
    def _is_parsable_file(self, file_path: str) -> bool:
        """
        Check if a file can be parsed.
        
        Args:
            file_path: Path to the file
            
        Returns:
            True if the file can be parsed, False otherwise
        """
        if not os.path.exists(file_path):
            return False
            
        # Check file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # List of parsable extensions
        parsable_extensions = ['.txt', '.json', '.csv', '.xml', '.log']
        
        return ext in parsable_extensions
        
    def _parse_file(self, file_path: str) -> Dict[str, Any]:
        """
        Parse a file and extract structured data.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary with extracted structured data
        """
        # Try plugin-based parsing first (for known file formats)
        for plugin in self.plugins:
            try:
                # Check the filename for clues
                filename = os.path.basename(file_path).lower()
                plugin_name = plugin.name.replace('_parser', '').lower()
                if plugin_name in filename:
                    logger.info(f"Using {plugin.name} to parse file {filename} based on filename match")
                    return plugin.parse_file(file_path)
            except Exception as e:
                logger.error(f"Plugin {plugin.name} failed to parse file: {str(e)}")
                
        # Fallback to generic parsing
        result = {}
        
        # Check file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        try:
            # Parse based on file type
            if ext == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Check for known data structures
                if isinstance(data, dict):
                    # Check for credentials
                    if 'username' in data and 'password' in data:
                        result.setdefault("credentials", []).append({
                            "username": data["username"],
                            "password": data["password"],
                            "domain": data.get("domain", self._extract_domain_from_username(data["username"]))
                        })
                        
                    # Check for cookies
                    if 'cookies' in data:
                        cookies = data['cookies']
                        if isinstance(cookies, list):
                            result.setdefault("cookies", []).extend([
                                {"domain": c.get("domain", ""), "value": c.get("value", "")}
                                for c in cookies if isinstance(c, dict)
                            ])
                        elif isinstance(cookies, dict):
                            result.setdefault("cookies", []).append({
                                "domain": data.get("domain", ""),
                                "value": str(cookies)
                            })
                            
                    # Check for system info
                    if 'system' in data or 'os' in data or 'hardware' in data:
                        system_info = {}
                        if 'system' in data:
                            system_info["full_info"] = str(data["system"])
                        if 'os' in data:
                            system_info["os"] = str(data["os"])
                        if 'hardware' in data:
                            system_info["hardware"] = str(data["hardware"])
                        if 'ip' in data:
                            system_info["ip"] = str(data["ip"])
                            
                        result["system_info"] = system_info
                        
            elif ext == '.txt':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Parse text similar to message text
                credentials = self._extract_credentials(text)
                if credentials:
                    result.setdefault("credentials", []).extend(credentials)
                    
                cookies = self._extract_cookies(text)
                if cookies:
                    result.setdefault("cookies", []).extend(cookies)
                    
                system_info = self._extract_system_info(text)
                if system_info:
                    result["system_info"] = system_info
                    
            elif ext == '.csv':
                # Process CSV (simplified)
                import csv
                credentials = []
                
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    reader = csv.reader(f)
                    headers = next(reader, None)
                    
                    if headers:
                        # Check for credential-like patterns in headers
                        username_idx = None
                        password_idx = None
                        domain_idx = None
                        
                        for i, header in enumerate(headers):
                            header_lower = header.lower()
                            if any(term in header_lower for term in ['email', 'username', 'user', 'login']):
                                username_idx = i
                            elif any(term in header_lower for term in ['password', 'pwd', 'pass']):
                                password_idx = i
                            elif any(term in header_lower for term in ['domain', 'site', 'service']):
                                domain_idx = i
                                
                        # Process rows if we found credential columns
                        if username_idx is not None and password_idx is not None:
                            for row in reader:
                                if len(row) > max(username_idx, password_idx):
                                    username = row[username_idx].strip()
                                    password = row[password_idx].strip()
                                    
                                    if username and password:
                                        credential = {
                                            "username": username,
                                            "password": password
                                        }
                                        
                                        # Add domain if available
                                        if domain_idx is not None and len(row) > domain_idx:
                                            domain = row[domain_idx].strip()
                                            if domain:
                                                credential["domain"] = domain
                                        else:
                                            # Try to extract domain from username
                                            domain = self._extract_domain_from_username(username)
                                            if domain:
                                                credential["domain"] = domain
                                                
                                        credentials.append(credential)
                                        
                        if credentials:
                            result.setdefault("credentials", []).extend(credentials)
                                
        except Exception as e:
            logger.error(f"Failed to parse file {file_path}: {str(e)}")
            
        return result
