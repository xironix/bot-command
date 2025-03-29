"""
Parser utilities for more resilient stealer log processing.

This module provides utilities to make parsing stealer logs more robust,
with flexible pattern matching, error handling, and validation.
"""

import re
import json
import logging
import time
from typing import Dict, List, Any, Optional, Tuple, Pattern, Union, Callable
from concurrent.futures import ThreadPoolExecutor
import zipfile
import os

logger = logging.getLogger(__name__)

class FlexiblePattern:
    """A more resilient pattern matching utility for stealer logs."""
    
    def __init__(self, name: str, priority: int = 1):
        """
        Initialize a flexible pattern.
        
        Args:
            name: Pattern name for debugging and logging
            priority: Pattern priority (higher values = more specific/reliable patterns)
        """
        self.name = name
        self.priority = priority
        self.regex_patterns = []
        self.json_paths = []
        self.validation_funcs = []
        self.match_count = 0
        self.attempt_count = 0
        
    def add_regex(self, pattern: Union[str, Pattern], flags: int = 0) -> 'FlexiblePattern':
        """
        Add a regex pattern variant.
        
        Args:
            pattern: Regular expression pattern (string or compiled)
            flags: Regex flags if pattern is a string
            
        Returns:
            Self for method chaining
        """
        if isinstance(pattern, str):
            try:
                compiled = re.compile(pattern, flags)
                self.regex_patterns.append(compiled)
            except re.error as e:
                logger.error(f"Invalid regex pattern in {self.name}: {e}")
        else:
            self.regex_patterns.append(pattern)
            
        return self
    
    def add_json_path(self, path: List[str]) -> 'FlexiblePattern':
        """
        Add a JSON path to search for.
        
        Args:
            path: List of keys forming a path in a JSON object
            
        Returns:
            Self for method chaining
        """
        self.json_paths.append(path)
        return self
        
    def add_validation(self, func: Callable[[Dict[str, Any]], bool]) -> 'FlexiblePattern':
        """
        Add a validation function for post-extraction verification.
        
        Args:
            func: Function taking extracted data and returning bool
            
        Returns:
            Self for method chaining
        """
        self.validation_funcs.append(func)
        return self
        
    def match_regex(self, text: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Try to match using regex patterns.
        
        Args:
            text: Text to match against
            
        Returns:
            Tuple of (success, extracted_data)
        """
        self.attempt_count += 1
        extracted = {}
        
        if not text:
            return False, {}
            
        for pattern in self.regex_patterns:
            try:
                matches = list(pattern.finditer(text))
                if matches:
                    # Extract named groups if available
                    for i, match in enumerate(matches):
                        if match.groupdict():
                            # Named groups
                            for name, value in match.groupdict().items():
                                if name not in extracted:
                                    extracted[name] = []
                                extracted[name].append(value)
                        elif match.groups():
                            # Unnamed groups - use pattern name with index
                            group_name = f"{self.name}_{i}"
                            if group_name not in extracted:
                                extracted[group_name] = []
                            extracted[group_name].append(match.groups())
                    
                    self.match_count += 1
                    return True, extracted
            except Exception as e:
                logger.warning(f"Error in regex pattern {self.name}: {str(e)}")
                
        return False, {}
        
    def match_json(self, obj: Any) -> Tuple[bool, Dict[str, Any]]:
        """
        Try to match against JSON paths.
        
        Args:
            obj: JSON object (dict or list)
            
        Returns:
            Tuple of (success, extracted_data)
        """
        self.attempt_count += 1
        
        if not obj or not isinstance(obj, (dict, list)):
            return False, {}
            
        extracted = {}
        matched = False
        
        for path in self.json_paths:
            try:
                current = obj
                valid_path = True
                
                # Navigate the path
                for key in path:
                    if isinstance(current, dict) and key in current:
                        current = current[key]
                    elif isinstance(current, list) and key.isdigit() and int(key) < len(current):
                        current = current[int(key)]
                    else:
                        valid_path = False
                        break
                        
                if valid_path:
                    # Got a match
                    path_name = ".".join(path)
                    extracted[path_name] = current
                    matched = True
            except Exception as e:
                logger.warning(f"Error in JSON path {'.'.join(path)}: {str(e)}")
                
        if matched:
            self.match_count += 1
            
        return matched, extracted
        
    def validate(self, data: Dict[str, Any]) -> bool:
        """
        Validate extracted data.
        
        Args:
            data: Extracted data dictionary
            
        Returns:
            True if valid, False otherwise
        """
        if not self.validation_funcs:
            return True
            
        for func in self.validation_funcs:
            try:
                if not func(data):
                    return False
            except Exception as e:
                logger.warning(f"Error in validation function for {self.name}: {str(e)}")
                return False
                
        return True
        
    def get_success_rate(self) -> float:
        """
        Get the success rate of this pattern.
        
        Returns:
            Success rate as float (0-1)
        """
        if self.attempt_count == 0:
            return 0.0
            
        return self.match_count / self.attempt_count


class PatternGroup:
    """A group of patterns for extracting structured data."""
    
    def __init__(self, name: str):
        """
        Initialize a pattern group.
        
        Args:
            name: Group name for debugging and logging
        """
        self.name = name
        self.patterns = []
        
    def add_pattern(self, pattern: FlexiblePattern) -> 'PatternGroup':
        """
        Add a pattern to the group.
        
        Args:
            pattern: FlexiblePattern instance
            
        Returns:
            Self for method chaining
        """
        self.patterns.append(pattern)
        return self
        
    def match(self, text: str, json_obj: Optional[Any] = None) -> Dict[str, Any]:
        """
        Try to match using all patterns in the group.
        
        Args:
            text: Text to match against
            json_obj: Optional JSON object to match against
            
        Returns:
            Dictionary of extracted data
        """
        result = {}
        
        # Sort patterns by priority (highest first)
        sorted_patterns = sorted(self.patterns, key=lambda p: p.priority, reverse=True)
        
        # Try regex matches
        if text:
            for pattern in sorted_patterns:
                success, data = pattern.match_regex(text)
                if success:
                    # Merge data
                    for key, value in data.items():
                        if key in result:
                            if isinstance(result[key], list) and isinstance(value, list):
                                result[key].extend(value)
                            else:
                                result[key] = value
                        else:
                            result[key] = value
        
        # Try JSON matches
        if json_obj:
            for pattern in sorted_patterns:
                success, data = pattern.match_json(json_obj)
                if success:
                    # Merge data
                    for key, value in data.items():
                        if key in result:
                            if isinstance(result[key], list) and isinstance(value, list):
                                result[key].extend(value)
                            else:
                                result[key] = value
                        else:
                            result[key] = value
                            
        return result
        
    def validate(self, data: Dict[str, Any]) -> bool:
        """
        Validate extracted data using all patterns.
        
        Args:
            data: Extracted data dictionary
            
        Returns:
            True if valid, False otherwise
        """
        for pattern in self.patterns:
            if not pattern.validate(data):
                return False
                
        return True


class RetryableOperation:
    """A utility for operations that need to be retried."""
    
    def __init__(self, max_retries: int = 3, delay_base: float = 1.0, 
                 backoff_factor: float = 2.0, logger_name: str = "RetryableOperation"):
        """
        Initialize a retryable operation.
        
        Args:
            max_retries: Maximum number of retry attempts
            delay_base: Base delay in seconds
            backoff_factor: Backoff multiplier for each retry
            logger_name: Name for the logger
        """
        self.max_retries = max_retries
        self.delay_base = delay_base
        self.backoff_factor = backoff_factor
        self.logger = logging.getLogger(logger_name)
        
    async def execute_async(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute an async function with retries.
        
        Args:
            func: Async function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Function result
            
        Raises:
            Exception: If all retries fail
        """
        import asyncio
        
        retries = 0
        last_error = None
        
        while retries <= self.max_retries:
            try:
                if retries > 0:
                    delay = self.delay_base * (self.backoff_factor ** (retries - 1))
                    self.logger.info(f"Retry {retries}/{self.max_retries} after {delay:.2f}s delay")
                    await asyncio.sleep(delay)
                    
                return await func(*args, **kwargs)
            except Exception as e:
                retries += 1
                last_error = e
                self.logger.warning(f"Attempt {retries} failed: {str(e)}")
                
                # If we're out of retries, raise the last error
                if retries > self.max_retries:
                    self.logger.error(f"All {self.max_retries} retry attempts failed")
                    raise last_error
                    
    def execute_sync(self, func: Callable, *args, **kwargs) -> Any:
        """
        Execute a synchronous function with retries.
        
        Args:
            func: Function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
            
        Returns:
            Function result
            
        Raises:
            Exception: If all retries fail
        """
        retries = 0
        last_error = None
        
        while retries <= self.max_retries:
            try:
                if retries > 0:
                    delay = self.delay_base * (self.backoff_factor ** (retries - 1))
                    self.logger.info(f"Retry {retries}/{self.max_retries} after {delay:.2f}s delay")
                    time.sleep(delay)
                    
                return func(*args, **kwargs)
            except Exception as e:
                retries += 1
                last_error = e
                self.logger.warning(f"Attempt {retries} failed: {str(e)}")
                
                # If we're out of retries, raise the last error
                if retries > self.max_retries:
                    self.logger.error(f"All {self.max_retries} retry attempts failed")
                    raise last_error


class EnhancedFileHandler:
    """Enhanced file handling for stealer logs."""
    
    def __init__(self, temp_dir: str = "temp_extracted"):
        """
        Initialize the file handler.
        
        Args:
            temp_dir: Directory for temporary extracted files
        """
        self.temp_dir = temp_dir
        self.max_workers = 2
        if not os.path.exists(temp_dir):
            os.makedirs(temp_dir, exist_ok=True)
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect file type using extensions and content inspection.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File type string
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return "unknown"
            
        # Get file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Check for archive types
        if ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            return ext[1:]  # Remove the dot
            
        # Check for known text formats
        if ext in ['.txt', '.log', '.json', '.csv', '.xml']:
            return ext[1:]  # Remove the dot
            
        # Try to detect by content
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
                # Check for zip signature
                if header.startswith(b'PK\x03\x04'):
                    return 'zip'
                    
                # Check for JSON content
                if header.startswith(b'{') or header.startswith(b'['):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as json_f:
                            json.loads(json_f.read())
                        return 'json'
                    except json.JSONDecodeError:
                        pass
                        
                # Simple text detection
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as text_f:
                        text = text_f.read(1024)
                        if text and text.isprintable():
                            return 'txt'
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Error detecting file type for {file_path}: {str(e)}")
            
        return "unknown"
        
    def extract_archive(self, file_path: str) -> List[str]:
        """
        Extract an archive file.
        
        Args:
            file_path: Path to the archive
            
        Returns:
            List of extracted file paths
        """
        extracted_files = []
        file_type = self.detect_file_type(file_path)
        
        if file_type == 'zip':
            try:
                # Create unique subfolder for this extraction
                extract_dir = os.path.join(self.temp_dir, os.path.basename(file_path) + "_extracted")
                os.makedirs(extract_dir, exist_ok=True)
                
                with zipfile.ZipFile(file_path, 'r') as zip_ref:
                    # Check for password protection
                    if any(info.flag_bits & 0x1 for info in zip_ref.infolist()):
                        logger.warning(f"Archive {file_path} is password protected")
                        
                        # Try with common stealer passwords
                        common_passwords = [b'infected', b'malware', b'password', b'1234', b'admin']
                        for password in common_passwords:
                            try:
                                zip_ref.extractall(path=extract_dir, pwd=password)
                                logger.info(f"Extracted archive with password {password}")
                                break
                            except Exception:
                                continue
                    else:
                        zip_ref.extractall(path=extract_dir)
                        
                # List extracted files
                for root, _, files in os.walk(extract_dir):
                    for file in files:
                        extracted_files.append(os.path.join(root, file))
            except Exception as e:
                logger.error(f"Failed to extract zip archive {file_path}: {str(e)}")
        # Add support for other archive types as needed
                
        return extracted_files
        
    def process_file_contents(self, file_path: str, parser_func: Callable[[str], Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process file contents with appropriate handling based on file type.
        
        Args:
            file_path: Path to the file
            parser_func: Function to parse text content
            
        Returns:
            Dictionary with structured data
        """
        result = {"credentials": [], "cookies": [], "system_info": {}, "file_paths": [], "parsing_errors": []}
        file_type = self.detect_file_type(file_path)
        
        # Handle based on file type
        if file_type in ['txt', 'log']:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    text = f.read()
                    
                # Parse text content
                text_result = parser_func(text)
                
                # Merge results
                for key, value in text_result.items():
                    if isinstance(value, list):
                        result[key].extend(value)
                    elif isinstance(value, dict) and isinstance(result.get(key), dict):
                        result[key].update(value)
                    else:
                        result[key] = value
            except Exception as e:
                result["parsing_errors"].append(f"Error processing text file {file_path}: {str(e)}")
                
        elif file_type == 'json':
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    try:
                        json_data = json.load(f)
                        
                        # If it's a valid JSON, use it for extraction
                        # Specific handling will depend on the stealer format
                        if isinstance(json_data, dict):
                            # Extract credentials if present
                            if "credentials" in json_data and isinstance(json_data["credentials"], list):
                                result["credentials"].extend(json_data["credentials"])
                                
                            # Extract system info if present
                            if "system" in json_data and isinstance(json_data["system"], dict):
                                result["system_info"].update(json_data["system"])
                                
                            # Extract cookies if present
                            if "cookies" in json_data and isinstance(json_data["cookies"], list):
                                result["cookies"].extend(json_data["cookies"])
                    except json.JSONDecodeError:
                        # If JSON parsing fails, try as text
                        f.seek(0)
                        text = f.read()
                        text_result = parser_func(text)
                        
                        # Merge results
                        for key, value in text_result.items():
                            if isinstance(value, list):
                                result[key].extend(value)
                            elif isinstance(value, dict) and isinstance(result.get(key), dict):
                                result[key].update(value)
                            else:
                                result[key] = value
            except Exception as e:
                result["parsing_errors"].append(f"Error processing JSON file {file_path}: {str(e)}")
                
        elif file_type in ['zip', 'rar', '7z']:
            # Extract and process archive
            extracted_files = self.extract_archive(file_path)
            
            # Process each extracted file in parallel
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {
                    executor.submit(self.process_file_contents, file, parser_func): file
                    for file in extracted_files
                }
                
                for future in future_to_file:
                    file = future_to_file[future]
                    try:
                        file_result = future.result()
                        
                        # Merge results
                        for key, value in file_result.items():
                            if isinstance(value, list):
                                result[key].extend(value)
                            elif isinstance(value, dict) and isinstance(result.get(key), dict):
                                result[key].update(value)
                            else:
                                result[key] = value
                    except Exception as e:
                        result["parsing_errors"].append(f"Error processing extracted file {file}: {str(e)}")
                        
        else:
            result["parsing_errors"].append(f"Unsupported file type: {file_type}")
            
        return result


# Common validation functions
def validate_credentials(creds: List[Dict[str, str]]) -> bool:
    """
    Validate credential data.
    
    Args:
        creds: List of credential dictionaries
        
    Returns:
        True if valid, False otherwise
    """
    if not creds or not isinstance(creds, list):
        return False
        
    for cred in creds:
        if not isinstance(cred, dict):
            return False
            
        # Check for username and password
        if not cred.get("username") or not cred.get("password"):
            # Allow for variations in field names
            if not (cred.get("user") and cred.get("pass")) and not (cred.get("login") and cred.get("password")):
                return False
                
    return True

def validate_system_info(info: Dict[str, str]) -> bool:
    """
    Validate system information.
    
    Args:
        info: System info dictionary
        
    Returns:
        True if valid, False otherwise
    """
    if not info or not isinstance(info, dict):
        return False
        
    # Check for at least one expected field
    expected_fields = ["os", "computer_name", "username", "ip", "hardware_id"]
    for field in expected_fields:
        if field in info and info[field]:
            return True
            
    return False

def validate_cookies(cookies: List[Dict[str, str]]) -> bool:
    """
    Validate cookie data.
    
    Args:
        cookies: List of cookie dictionaries
        
    Returns:
        True if valid, False otherwise
    """
    if not cookies or not isinstance(cookies, list):
        return False
        
    for cookie in cookies:
        if not isinstance(cookie, dict):
            return False
            
        # Check for domain or value
        if not cookie.get("domain") and not cookie.get("value"):
            return False
            
    return True
