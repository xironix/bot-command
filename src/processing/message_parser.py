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
import asyncio

logger = logging.getLogger(__name__)

class MessageParser:
    """Parser for intercepted stealer bot messages."""
    
    def __init__(self):
        """Initialize message parser."""
        # Load parser configuration and fallback patterns
        self._load_patterns()
        
        # Initialize parser plugins
        self._initialize_plugins()
        
        # Create lock for thread-safe updates to stats
        self.stats_lock = asyncio.Lock()
        
        # Track parsing statistics
        self.stats = {
            "total_processed": 0,
            "successful_credential_extractions": 0,
            "successful_cookie_extractions": 0,
            "successful_system_info_extractions": 0,
            "successful_crypto_wallet_extractions": 0,
            "successful_credit_card_extractions": 0,  # Added for credit card tracking
            "high_value_extractions": 0,  # Count of high-value logs (>70 score)
            "very_high_value_extractions": 0, # Count of extremely valuable logs (>90 score)
            "plugin_successes": 0,        # Count of successful plugin parses
            "plugin_failures": 0,         # Count of plugin failures
            "failed_parsings": 0,
            "pattern_failures": {},       # Track which patterns are failing most often
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
            # Email/password combinations - more flexible with optional spaces and separators
            re.compile(r"(?:login|email|username|user|account)[\s:]*([^\s@]+@[^\s@]+\.[^\s@]+)[\s\r\n]*(?:password|pwd|pass|passwd)[\s:]*([^\s\r\n]+)", re.IGNORECASE),
            # Generic username/password combinations - more flexible with optional spaces
            re.compile(r"(?:username|user|login|account)[\s:]*([^\s\r\n]{3,})[\s\r\n]*(?:password|pwd|pass|passwd)[\s:]*([^\s\r\n]+)", re.IGNORECASE),
            # Domain-specific credentials - more flexible separators
            re.compile(r"(?:site|domain|service|url|website)[\s:]*([^\s\r\n]+)[\s\r\n]*(?:username|user|login|email|account)[\s:]*([^\s\r\n]+)[\s\r\n]*(?:password|pwd|pass|passwd)[\s:]*([^\s\r\n]+)", re.IGNORECASE),
            # Alternative format with title/header - more flexible with optional spaces
            re.compile(r"(?:credentials|account|login info)[\s\r\n]*(?:site|domain|service|url|website)[\s:]*([^\s\r\n]+)[\s\r\n]*(?:username|user|login|email)[\s:]*([^\s\r\n]+)[\s\r\n]*(?:password|pwd|pass)[\s:]*([^\s\r\n]+)", re.IGNORECASE),
            # Key-value pairs format - more flexible with various separators
            re.compile(r"username[\s:]*([^\r\n]+)[\r\n]+password[\s:]*([^\r\n]+)", re.IGNORECASE),
            # URL with credentials embedded - more flexible domains and separators
            re.compile(r"(?:url|link)[\s:]*(?:https?://)?(?:www\.)?([^/\s]+)(?:[^\r\n]*)[\r\n]*(?:username|user|login|email)[\s:]*([^\s\r\n]+)[\s\r\n]*(?:password|pwd|pass)[\s:]*([^\s\r\n]+)", re.IGNORECASE),
        ]
        
        # Cookie patterns
        self._cookie_patterns = [
            # Standard cookie format - more flexible with optional spaces
            re.compile(r"(?:cookie|cookies)[\s:]*(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
            # Domain-specific cookies - more flexible with optional spaces
            re.compile(r"domain[\s:]*([^\s\r\n]+)[\s\r\n]*(?:cookie|cookies)[\s:]*(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
            # Cookie with name/value pairs - more flexible with optional spaces
            re.compile(r"(?:cookie|cookies)[\s:]*([^=\s]+)=([^;\s]+)", re.IGNORECASE),
            # Browser cookie format - more flexible with optional spaces
            re.compile(r"(?:browser|chrome|firefox|edge|safari)[\s:]*(?:cookie|cookies)[\s:]*(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
        ]
        
        # System info patterns
        self._system_info_patterns = [
            # OS and version - more flexible with optional spaces
            re.compile(r"(?:os|operating system|system)[\s:]*([^\s\r\n][^\r\n]+)", re.IGNORECASE),
            # Hardware info - more flexible with optional spaces
            re.compile(r"(?:hardware|pc|computer|device|machine|system)[\s:]*([^\s\r\n][^\r\n]+)", re.IGNORECASE),
            # IP addresses (IPv4 and IPv6) - more flexible with optional spaces
            re.compile(r"(?:ip|address|ipv4)[\s:]*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", re.IGNORECASE),
            re.compile(r"(?:ipv6|ip)[\s:]*([0-9a-fA-F:]+)", re.IGNORECASE),
            # Full system info blocks - more flexible with optional spaces
            re.compile(r"(?:system info|sysinfo|system information|pc info|computer info|device info)[\s:]*(.+?)(?=\n\n|\Z)", re.IGNORECASE | re.DOTALL),
            # Windows version specific - more flexible with optional spaces
            re.compile(r"(?:windows|win)[\s:]*([^\s\r\n][^\r\n]+)", re.IGNORECASE),
            # MAC address - more flexible with optional spaces
            re.compile(r"(?:mac address|mac|physical address)[\s:]*([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", re.IGNORECASE),
            # Username/hostname format - more flexible with optional spaces
            re.compile(r"(?:username|user|hostname|computer name)[\s:]*([^\s\r\n][^\r\n]+)", re.IGNORECASE),
        ]
        
        # Add JSON detection patterns for identifying JSON-formatted logs
        self._json_patterns = [
            # Standard JSON object pattern
            re.compile(r'\{\s*"[^"]+"\s*:\s*["{[]')
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
        # Use non-blocking approach to acquire the lock
        # This is safe because we're inside an async function (coordinator._process_message)
        # that was submitted to the monitor_worker via submit_monitor_task
        loop = asyncio.get_event_loop()
        loop.create_task(self._increment_stat("total_processed"))
        
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
            "credit_cards": [],    # Added for credit card data
            "ftp_credentials": [], # Added for FTP credential data
            "messenger_tokens": [], # Added for chat app tokens
            "sso_tokens": [],      # Added for SSO tokens
            "two_factor_codes": [], # Added for 2FA backup codes
            "file_paths": [],
            "value_score": 0,      # Added for value scoring
            "parsing_errors": []
        }
        
        # Extract text content
        text = message_data.get("text", "")
        
        try:
            # Try JSON parsing first if it looks like JSON
            # This comes before plugin-based parsing as some plugins might benefit from pre-parsed JSON
            json_data = None
            is_json = any(p.search(text) for p in self._json_patterns)
            
            if is_json:
                try:
                    # Try to parse the entire text as JSON
                    json_data = json.loads(text)
                    if self.debug_mode:
                        self.current_debug_data = {
                            "message_id": message_data.get("message_id", "unknown"),
                            "bot_id": message_data.get("bot_id", "unknown"),
                            "bot_username": message_data.get("bot_username", "unknown"),
                            "timestamp": datetime.utcnow().isoformat(),
                            "text_length": len(message_data.get("text", "")),
                            "has_media": message_data.get("has_media", False),
                            "media_path": message_data.get("media_path", None),
                            "json_parsed": True,
                            "plugin_detection": {},
                            "selected_plugin": None,
                            "extraction_details": {},
                            "fallback_patterns": [],
                            "errors": []
                        }
                except json.JSONDecodeError:
                    # If the entire text isn't valid JSON, try to extract JSON objects
                    try:
                        # Look for JSON objects in text (common in logs)
                        json_start = re.search(r"\{\s*\"", text)
                        if json_start:
                            # Try to find a complete JSON object
                            # Count braces to handle nested objects
                            start_idx = json_start.start()
                            brace_count = 0
                            for i in range(start_idx, len(text)):
                                if text[i] == '{':
                                    brace_count += 1
                                elif text[i] == '}':
                                    brace_count -= 1
                                    if brace_count == 0:
                                        # Found the end of the JSON object
                                        json_str = text[start_idx:i+1]
                                        try:
                                            json_data = json.loads(json_str)
                                            if self.debug_mode:
                                                self.current_debug_data = {
                                                    "message_id": message_data.get("message_id", "unknown"),
                                                    "bot_id": message_data.get("bot_id", "unknown"),
                                                    "bot_username": message_data.get("bot_username", "unknown"),
                                                    "timestamp": datetime.utcnow().isoformat(),
                                                    "text_length": len(message_data.get("text", "")),
                                                    "has_media": message_data.get("has_media", False),
                                                    "media_path": message_data.get("media_path", None),
                                                    "json_parsed": True,
                                                    "json_snippet": True,
                                                    "plugin_detection": {},
                                                    "selected_plugin": None,
                                                    "extraction_details": {},
                                                    "fallback_patterns": [],
                                                    "errors": []
                                                }
                                            break
                                        except json.JSONDecodeError:
                                            # This wasn't a valid JSON object, continue searching
                                            pass
                    except Exception as e:
                        logger.debug(f"Error extracting JSON object: {str(e)}")
                        
            # If we have JSON, augment message_data with it
            if json_data:
                message_data_with_json = message_data.copy()
                message_data_with_json["json_data"] = json_data
            else:
                message_data_with_json = message_data
                
            # Try plugin-based parsing (now potentially with JSON data)
            if self.plugins:
                # Initialize debug data for this message if not already done
                if self.debug_mode and not self.current_debug_data:
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
                matching_plugins = []
                
                for plugin in self.plugins:
                    # Record attempt statistics using async task
                    loop.create_task(self._update_plugin_stat(plugin.name, "attempts"))
                    
                    # Try to pass json_data if available
                    if "json_data" in message_data_with_json:
                        can_parse, confidence = plugin.can_parse(message_data_with_json)
                    else:
                        can_parse, confidence = plugin.can_parse(message_data)
                    
                    # Record plugin detection attempt in debug data
                    if self.debug_mode:
                        self.current_debug_data["plugin_detection"][plugin.name] = {
                            "can_parse": can_parse,
                            "confidence": confidence,
                            "threshold": plugin.confidence_threshold
                        }
                    
                    # Track plugins that exceed the confidence threshold
                    if can_parse and confidence >= plugin.confidence_threshold:
                        matching_plugins.append((plugin, confidence))
                        
                        # Update best plugin if this one has higher confidence
                        if confidence > best_confidence:
                            best_plugin = plugin
                            best_confidence = confidence
                
                # Log ambiguity when multiple plugins match with high confidence
                if len(matching_plugins) > 1:
                    plugins_info = ", ".join([f"{p[0].name}({p[1]:.2f})" for p in matching_plugins])
                    logger.info(f"Multiple plugins matched message: {plugins_info} - using {best_plugin.name} with highest confidence")
                    
                    # Add this to debug data
                    if self.debug_mode:
                        self.current_debug_data["plugin_ambiguity"] = {
                            "matching_plugins": plugins_info,
                            "selected": best_plugin.name
                        }
                        
                # If we found a suitable plugin, use it
                if best_plugin and best_confidence >= best_plugin.confidence_threshold:
                    try:
                        logger.info(f"Using {best_plugin.name} to parse message (confidence: {best_confidence:.2f})")
                        
                        # Use message_data_with_json if available
                        if "json_data" in message_data_with_json:
                            plugin_result = best_plugin.parse(message_data_with_json)
                        else:
                            plugin_result = best_plugin.parse(message_data)
                        
                        # Perform post-parse validation
                        validation_passed = self._validate_plugin_result(best_plugin.name, plugin_result)
                        if not validation_passed:
                            warning_msg = f"Warning: {best_plugin.name} parse result failed validation checks"
                            logger.warning(warning_msg)
                            result["parsing_errors"].append(warning_msg)
                            if self.debug_mode:
                                self.current_debug_data["validation_warning"] = warning_msg
                        
                        # Merge plugin results into our result structure
                        for key in ["credentials", "cookies", "file_paths", "credit_cards", 
                                   "ftp_credentials", "messenger_tokens", "sso_tokens", 
                                   "two_factor_codes"]:
                            if key in plugin_result and plugin_result[key]:
                                result[key] = plugin_result[key]
                                if key == "credentials":
                                    loop.create_task(self._increment_stat("successful_credential_extractions"))
                                elif key == "cookies":
                                    loop.create_task(self._increment_stat("successful_cookie_extractions"))
                                elif key == "credit_cards":
                                    loop.create_task(self._increment_stat("successful_credit_card_extractions"))
                                    
                        # Merge system info if present
                        if "system_info" in plugin_result and plugin_result["system_info"]:
                            result["system_info"] = plugin_result["system_info"]
                            loop.create_task(self._increment_stat("successful_system_info_extractions"))
                            
                        # Add any crypto wallet data
                        if "crypto_wallets" in plugin_result and plugin_result["crypto_wallets"]:
                            result["crypto_wallets"] = plugin_result["crypto_wallets"]
                            
                        # Add any parsing errors
                        if "parsing_errors" in plugin_result and plugin_result["parsing_errors"]:
                            result["parsing_errors"].extend(plugin_result["parsing_errors"])
                            
                        # Add value score if available
                        if "value_score" in plugin_result:
                            result["value_score"] = plugin_result["value_score"]
                            
                        # Record plugin success statistics - using async tasks to avoid blocking
                        loop.create_task(self._increment_stat("plugin_successes"))
                        loop.create_task(self._update_plugin_stat(best_plugin.name, "successes"))
                        loop.create_task(self._update_plugin_avg(best_plugin.name, "avg_confidence", best_confidence))
                        
                        if "value_score" in plugin_result:
                            loop.create_task(self._update_plugin_avg(
                                best_plugin.name, 
                                "avg_value_score", 
                                plugin_result["value_score"]
                            ))
                            
                            # Track high-value extractions
                            if plugin_result["value_score"] > 70:
                                loop.create_task(self._increment_stat("high_value_extractions"))
                                
                            # Track extremely high-value extractions
                            if plugin_result["value_score"] > 90:
                                loop.create_task(self._increment_stat("very_high_value_extractions"))
                                
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
                        
                        # Record plugin failure statistics using async tasks
                        loop.create_task(self._increment_stat("plugin_failures"))
                        loop.create_task(self._update_plugin_stat(best_plugin.name, "failures"))
                        
                        # Continue with generic parsing as fallback
                
            # Apply generic regex parsing as fallback
            if self.debug_mode:
                self.current_debug_data["fallback_reason"] = "No matching plugin or plugin failure"
            
            # Extract credentials
            credentials = self._extract_credentials(text)
            if credentials:
                result["credentials"] = credentials
                loop.create_task(self._increment_stat("successful_credential_extractions"))
                
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
                loop.create_task(self._increment_stat("successful_cookie_extractions"))
                
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
                loop.create_task(self._increment_stat("successful_system_info_extractions"))
                
                # Debug info for system info extraction
                if self.debug_mode:
                    self.current_debug_data["fallback_patterns"].append({
                        "type": "system_info",
                        "details": system_info
                    })
                
            # Track other data type extractions
            if result.get("crypto_wallets"):
                loop.create_task(self._increment_stat("successful_crypto_wallet_extractions"))
                
            if result.get("credit_cards"):
                loop.create_task(self._increment_stat("successful_credit_card_extractions"))
                
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
            # Use async task for thread-safe increment
            loop = asyncio.get_event_loop()
            loop.create_task(self._increment_stat("failed_parsings"))
        
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
            
    async def _increment_stat(self, stat_key, increment=1):
        """
        Thread-safe increment of a stat counter.
        
        Args:
            stat_key: Key of the stat to increment
            increment: Value to increment by (default: 1)
        """
        async with self.stats_lock:
            if stat_key in self.stats:
                self.stats[stat_key] += increment
    
    async def _update_plugin_stat(self, plugin_name, stat_key, increment=1):
        """
        Thread-safe update of a plugin-specific stat.
        
        Args:
            plugin_name: Name of the plugin
            stat_key: Key of the stat to update
            increment: Value to increment by (default: 1)
        """
        async with self.stats_lock:
            if plugin_name in self.stats["plugins"] and stat_key in self.stats["plugins"][plugin_name]:
                self.stats["plugins"][plugin_name][stat_key] += increment
    
    async def _update_plugin_avg(self, plugin_name, avg_key, new_value):
        """
        Thread-safe update of a plugin average value.
        
        Args:
            plugin_name: Name of the plugin
            avg_key: Key of the average stat to update
            new_value: New value to include in the average
        """
        async with self.stats_lock:
            if plugin_name in self.stats["plugins"] and avg_key in self.stats["plugins"][plugin_name]:
                plugin_stats = self.stats["plugins"][plugin_name]
                if avg_key == "avg_confidence":
                    attempts = plugin_stats["attempts"]
                    if attempts > 0:
                        plugin_stats[avg_key] = (
                            (plugin_stats[avg_key] * (attempts - 1) + new_value) / attempts
                        )
                elif avg_key == "avg_value_score":
                    successes = plugin_stats["successes"]
                    if successes > 0:
                        plugin_stats[avg_key] = (
                            (plugin_stats[avg_key] * (successes - 1) + new_value) / successes
                        )
    
    async def _update_pattern_failure(self, failure_key):
        """
        Thread-safe update of pattern failure counter.
        
        Args:
            failure_key: Key of the pattern that failed
        """
        async with self.stats_lock:
            if failure_key not in self.stats["pattern_failures"]:
                self.stats["pattern_failures"][failure_key] = 0
            self.stats["pattern_failures"][failure_key] += 1
    
    async def get_parser_stats(self) -> Dict[str, Any]:
        """
        Get statistics on parser performance.
        
        Returns:
            Dictionary with parser statistics including plugin performance
        """
        async with self.stats_lock:
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
        # Add archive extensions that can be extracted
        archive_extensions = ['.zip', '.rar', '.7z', '.tar', '.gz']
        
        # Check file size is not too large (limit to 10MB for safety)
        try:
            file_size = os.path.getsize(file_path)
            if file_size > 10 * 1024 * 1024:  # 10MB
                logger.warning(f"File too large to parse: {file_path} ({file_size / (1024*1024):.2f} MB)")
                return False
        except Exception as e:
            logger.error(f"Error checking file size for {file_path}: {str(e)}")
            return False
        
        # Check if it's a directly parsable file or archive
        if ext in parsable_extensions or ext in archive_extensions:
            return True
            
        # Try to detect file type by content (first 4KB)
        try:
            with open(file_path, "rb") as f:
                header = f.read(4096)
                
            # Check for text file markers
            text_markers = [b'\n', b'\r', b' ', b'\t', b'{', b'[']
            if any(marker in header for marker in text_markers) and not b'\x00' in header:
                # Likely a text file
                return True
                
            # Check for ZIP file signature
            if header.startswith(b'PK\x03\x04'):
                return True
                
            # Check for JSON structure
            try:
                text_start = header.decode('utf-8', errors='ignore').strip()
                if text_start.startswith('{') or text_start.startswith('['):
                    return True
            except:
                pass
        except Exception as e:
            logger.error(f"Error examining file content for {file_path}: {str(e)}")
            
        return False
        
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
                
        # Check if file is an archive and extract contents
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        if ext in ['.zip', '.tar', '.gz', '.tgz']:
            extracted_results = self._process_archive(file_path)
            if extracted_results:
                return extracted_results
        
        # Fallback to generic parsing
        result = {}
        
        # Check file extension
        
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
                                        
                                        credentials.append(credential)
                                        
                        if credentials:
                            result.setdefault("credentials", []).extend(credentials)
                                
        except Exception as e:
            logger.error(f"Failed to parse file {file_path}: {str(e)}")
            
        return result
        
    def _validate_plugin_result(self, plugin_name: str, plugin_result: Dict[str, Any]) -> bool:
        """
        Perform basic validation on plugin parsing results.
        
        This checks if the plugin identified the correct type of data it should be able to parse.
        For example, RedLine stealer should always have system_info with a hardware_id.
        
        Args:
            plugin_name: Name of the plugin that generated the result
            plugin_result: Parsed data from the plugin
            
        Returns:
            True if validation passes, False otherwise
        """
        if not plugin_result:
            return False
            
        # Track if any validations failed
        validation_issues = []
            
        # Plugin-specific validations
        if plugin_name == "redline_stealer_parser":
            # RedLine should always extract system_info with hardware_id
            if (not plugin_result.get("system_info") or 
                not plugin_result["system_info"].get("hardware_id")):
                validation_issues.append("RedLine parser didn't extract hardware_id")
                
            # RedLine should typically extract browser credentials
            if not plugin_result.get("credentials"):
                validation_issues.append("RedLine parser didn't extract any credentials")
                
        elif plugin_name == "raccoon_stealer_parser":
            # Raccoon should typically have some form of browser data
            if (not plugin_result.get("credentials") and 
                not plugin_result.get("cookies")):
                validation_issues.append("Raccoon parser didn't extract any browser data")
                
        elif plugin_name == "vidar_stealer_parser":
            # Vidar usually includes system info and credentials
            if not plugin_result.get("system_info"):
                validation_issues.append("Vidar parser didn't extract system info")
                
        elif plugin_name == "azorult_parser":
            # Azorult often includes credentials and system data
            if (not plugin_result.get("credentials") and 
                not plugin_result.get("system_info")):
                validation_issues.append("Azorult parser didn't extract credentials or system info")
                
            # Azorult often extracts credit cards
            if not plugin_result.get("credit_cards"):
                validation_issues.append("Azorult parser didn't extract any credit cards")
                
        elif plugin_name == "snake_stealer_parser":
            # SnakeStealer specializes in SSO tokens, should have found some
            if not plugin_result.get("sso_tokens"):
                validation_issues.append("SnakeStealer parser didn't extract any SSO tokens")
                
        # Generic validations for all plugins
        total_extraction_count = (
            len(plugin_result.get("credentials", [])) +
            len(plugin_result.get("cookies", [])) +
            len(plugin_result.get("crypto_wallets", [])) +
            len(plugin_result.get("credit_cards", [])) +
            len(plugin_result.get("ftp_credentials", [])) +
            len(plugin_result.get("messenger_tokens", [])) +
            len(plugin_result.get("sso_tokens", [])) +
            len(plugin_result.get("two_factor_codes", []))
        )
        
        # If plugin found nothing, that's suspicious
        if total_extraction_count == 0 and not plugin_result.get("system_info"):
            validation_issues.append(f"Plugin {plugin_name} didn't extract any useful data")
            
        # Log any validation issues
        if validation_issues:
            for issue in validation_issues:
                logger.warning(f"Plugin validation issue: {issue}")
                
            # Increment pattern failures counter using async task
            validation_issue_key = f"{plugin_name}_validation"
            loop = asyncio.get_event_loop()
            loop.create_task(self._update_pattern_failure(validation_issue_key))
            
            return False
            
        return True
    def _process_archive(self, archive_path: str) -> Dict[str, Any]:
        """
        Extract and process files from an archive.
        
        Args:
            archive_path: Path to the archive file
            
        Returns:
            Dictionary with extracted structured data from all contained files
        """
        import tempfile
        import zipfile
        import tarfile
        import shutil
        from pathlib import Path
        
        # Create a temporary directory for extraction
        temp_dir = tempfile.mkdtemp(prefix="botcommand_extract_")
        logger.info(f"Extracting archive {archive_path} to {temp_dir}")
        
        extracted_files = []
        try:
            # Extract based on file type
            _, ext = os.path.splitext(archive_path)
            ext = ext.lower()
            
            # Handle ZIP files
            if ext == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    # Check for potential zip bombs
                    total_size = sum(info.file_size for info in zip_ref.infolist())
                    if total_size > 100 * 1024 * 1024:  # 100MB limit
                        logger.warning(f"Zip file too large to extract: {archive_path} ({total_size / (1024*1024):.2f} MB)")
                        return {}
                        
                    # Extract all files
                    zip_ref.extractall(temp_dir)
                    extracted_files = [os.path.join(temp_dir, f) for f in zip_ref.namelist() 
                                      if not f.endswith('/') and os.path.exists(os.path.join(temp_dir, f))]
            
            # Handle TAR files (including .tar.gz)
            elif ext in ['.tar', '.gz', '.tgz']:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    # Check for potential tar bombs
                    total_size = sum(m.size for m in tar_ref.getmembers() if m.isfile())
                    if total_size > 100 * 1024 * 1024:  # 100MB limit
                        logger.warning(f"Tar file too large to extract: {archive_path} ({total_size / (1024*1024):.2f} MB)")
                        return {}
                        
                    # Filter out dangerous paths (absolute, parent directory traversal)
                    safe_members = [m for m in tar_ref.getmembers() 
                                   if not m.name.startswith('/') and '..' not in m.name]
                    
                    # Extract safe members
                    for member in safe_members:
                        tar_ref.extract(member, temp_dir)
                        
                    extracted_files = [os.path.join(temp_dir, m.name) for m in safe_members 
                                      if m.isfile() and os.path.exists(os.path.join(temp_dir, m.name))]
            
            # Process each extracted file
            result = {
                "credentials": [],
                "cookies": [],
                "system_info": {},
                "crypto_wallets": [],
                "file_paths": [],
                "credit_cards": [],
                "ftp_credentials": [],
                "messenger_tokens": [],
                "sso_tokens": [],
                "two_factor_codes": [],
                "parsing_errors": []
            }
            
            for file_path in extracted_files:
                if self._is_parsable_file(file_path):
                    try:
                        file_result = self._parse_file(file_path)
                        
                        # Merge results
                        for key in ["credentials", "cookies", "crypto_wallets", "file_paths", 
                                   "credit_cards", "ftp_credentials", "messenger_tokens", 
                                   "sso_tokens", "two_factor_codes", "parsing_errors"]:
                            if key in file_result and file_result[key]:
                                result[key].extend(file_result[key])
                                
                        # Merge system_info dict
                        if file_result.get("system_info"):
                            result["system_info"].update(file_result["system_info"])
                            
                    except Exception as e:
                        error_msg = f"Error processing extracted file {file_path}: {str(e)}"
                        logger.error(error_msg)
                        result["parsing_errors"].append(error_msg)
                        
            return result
            
        except Exception as e:
            logger.error(f"Error extracting archive {archive_path}: {str(e)}")
            return {}
        finally:
            # Clean up temporary directory
            try:
                shutil.rmtree(temp_dir)
            except Exception as e:
                logger.error(f"Error cleaning up temporary directory {temp_dir}: {str(e)}")
