"""
File handling utilities for Bot-Command.

This module provides standardized file handling utilities for downloading,
processing, and extracting files with proper error handling.
"""

import os
import json
import logging
import shutil
import tempfile
import zipfile
import tarfile
import csv
from typing import Dict, List, Any, Optional, Callable, Union
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

class FileHandler:
    """
    Standardized file handling utility.
    
    This class provides methods for file type detection, content extraction,
    and structured data parsing.
    """
    
    def __init__(self, temp_dir: str = "temp_extracted", max_workers: int = 2, 
                max_size_mb: int = 10):
        """
        Initialize file handler.
        
        Args:
            temp_dir: Directory for temporary extracted files
            max_workers: Maximum number of parallel file processing workers
            max_size_mb: Maximum allowed file size in MB for processing
        """
        self.temp_dir = temp_dir
        self.max_workers = max_workers
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Create temp directory if it doesn't exist
        os.makedirs(temp_dir, exist_ok=True)
        
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect file type using extensions and content inspection.
        
        Args:
            file_path: Path to the file
            
        Returns:
            File type string ('json', 'txt', 'zip', 'csv', etc.)
        """
        # Check if file exists
        if not os.path.exists(file_path):
            return "unknown"
            
        # Check file size
        try:
            file_size = os.path.getsize(file_path)
            if file_size > self.max_size_bytes:
                logger.warning(f"File too large to process: {file_path} " 
                              f"({file_size / (1024*1024):.2f}MB > " 
                              f"{self.max_size_bytes / (1024*1024)}MB)")
                return "too_large"
        except Exception as e:
            logger.error(f"Error checking file size: {str(e)}")
            
        # Get file extension
        _, ext = os.path.splitext(file_path)
        ext = ext.lower()
        
        # Check for known extensions
        if ext in ['.zip', '.jar']:
            return 'zip'
        elif ext in ['.tar', '.gz', '.tgz']:
            return 'tar'
        elif ext == '.json':
            return 'json'
        elif ext in ['.txt', '.log']:
            return 'txt'
        elif ext == '.csv':
            return 'csv'
        elif ext == '.xml':
            return 'xml'
            
        # Try to detect by content
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
                # Check for zip signature
                if header.startswith(b'PK\x03\x04'):
                    return 'zip'
                    
                # Check for gzip signature
                if header.startswith(b'\x1f\x8b'):
                    return 'tar'
                    
                # Check for JSON content
                if header.startswith(b'{') or header.startswith(b'['):
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as json_f:
                            json.loads(json_f.read(1024))  # Read first 1KB only
                        return 'json'
                    except json.JSONDecodeError:
                        pass
                        
                # Simple text detection
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as text_f:
                        text = text_f.read(1024)
                        if text and all(c.isprintable() or c.isspace() for c in text):
                            # Check for CSV structure
                            if ',' in text and '\n' in text:
                                # Count commas in first lines
                                lines = text.splitlines()[:5]  # Check first 5 lines
                                if lines and all(line.count(',') == lines[0].count(',') for line in lines):
                                    return 'csv'
                            return 'txt'
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Error detecting file type for {file_path}: {str(e)}")
            
        return "unknown"
        
    def extract_archive(self, file_path: str) -> List[str]:
        """
        Extract an archive file safely.
        
        Args:
            file_path: Path to the archive
            
        Returns:
            List of extracted file paths
        """
        extracted_files = []
        file_type = self.detect_file_type(file_path)
        
        if file_type not in ['zip', 'tar']:
            logger.warning(f"Cannot extract {file_path}: not an archive")
            return []
            
        # Create unique subdirectory for this extraction
        extract_dir = os.path.join(
            self.temp_dir, 
            os.path.basename(file_path).replace('.', '_') + "_extracted"
        )
        os.makedirs(extract_dir, exist_ok=True)
        
        try:
            if file_type == 'zip':
                self._extract_zip(file_path, extract_dir, extracted_files)
            elif file_type == 'tar':
                self._extract_tar(file_path, extract_dir, extracted_files)
        except Exception as e:
            logger.error(f"Failed to extract archive {file_path}: {str(e)}")
            
        return extracted_files
        
    def _extract_zip(self, file_path: str, extract_dir: str, extracted_files: List[str]) -> None:
        """
        Extract a ZIP archive.
        
        Args:
            file_path: Path to the ZIP file
            extract_dir: Directory to extract to
            extracted_files: List to append extracted file paths to
        """
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            # Check for potential zip bomb
            total_size = sum(info.file_size for info in zip_ref.infolist())
            if total_size > self.max_size_bytes:
                logger.warning(f"ZIP file too large to extract: {file_path} "
                              f"({total_size / (1024*1024):.2f}MB > "
                              f"{self.max_size_bytes / (1024*1024)}MB)")
                return
                
            # Check for password protection
            if any(info.flag_bits & 0x1 for info in zip_ref.infolist()):
                logger.warning(f"ZIP file {file_path} is password protected")
                
                # Try with common stealer passwords
                common_passwords = [b'infected', b'malware', b'password', b'1234', b'admin']
                for password in common_passwords:
                    try:
                        zip_ref.extractall(path=extract_dir, pwd=password)
                        logger.info(f"Extracted ZIP with password {password}")
                        break
                    except Exception:
                        if password == common_passwords[-1]:
                            logger.warning(f"Failed to extract password-protected ZIP with common passwords")
                        continue
            else:
                # Filter out unsafe paths
                members = []
                for info in zip_ref.infolist():
                    if info.filename.startswith('/') or '..' in info.filename:
                        logger.warning(f"Skipping potentially unsafe path in ZIP: {info.filename}")
                    else:
                        members.append(info)
                
                # Extract safe members
                for member in members:
                    try:
                        zip_ref.extract(member, path=extract_dir)
                    except Exception as e:
                        logger.warning(f"Failed to extract {member.filename}: {str(e)}")
                        
            # Get paths of extracted files
            for root, _, files in os.walk(extract_dir):
                for file in files:
                    extracted_files.append(os.path.join(root, file))
                    
    def _extract_tar(self, file_path: str, extract_dir: str, extracted_files: List[str]) -> None:
        """
        Extract a TAR/GZ archive.
        
        Args:
            file_path: Path to the TAR file
            extract_dir: Directory to extract to
            extracted_files: List to append extracted file paths to
        """
        with tarfile.open(file_path, 'r:*') as tar_ref:
            # Check for potential tar bomb
            total_size = sum(m.size for m in tar_ref.getmembers() if m.isfile())
            if total_size > self.max_size_bytes:
                logger.warning(f"TAR file too large to extract: {file_path} "
                              f"({total_size / (1024*1024):.2f}MB > "
                              f"{self.max_size_bytes / (1024*1024)}MB)")
                return
                
            # Filter out unsafe paths
            safe_members = []
            for member in tar_ref.getmembers():
                if member.name.startswith('/') or '..' in member.name:
                    logger.warning(f"Skipping potentially unsafe path in TAR: {member.name}")
                else:
                    safe_members.append(member)
                    
            # Extract safe members
            for member in safe_members:
                try:
                    tar_ref.extract(member, path=extract_dir)
                    if member.isfile():
                        extracted_files.append(os.path.join(extract_dir, member.name))
                except Exception as e:
                    logger.warning(f"Failed to extract {member.name}: {str(e)}")
                    
    def process_file(self, file_path: str, parser_func: Optional[Callable[[str], Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Process a file based on its type and extract structured data.
        
        Args:
            file_path: Path to the file
            parser_func: Optional function to parse text content
            
        Returns:
            Dictionary with extracted structured data
        """
        result = {
            "credentials": [],
            "cookies": [],
            "system_info": {},
            "crypto_wallets": [],
            "file_paths": [],
            "credit_cards": [],
            "parsing_errors": []
        }
        
        if not os.path.exists(file_path):
            result["parsing_errors"].append(f"File does not exist: {file_path}")
            return result
            
        file_type = self.detect_file_type(file_path)
        
        # Handle based on file type
        try:
            if file_type == 'txt':
                self._process_text_file(file_path, result, parser_func)
            elif file_type == 'json':
                self._process_json_file(file_path, result, parser_func)
            elif file_type == 'csv':
                self._process_csv_file(file_path, result)
            elif file_type in ['zip', 'tar']:
                extracted_files = self.extract_archive(file_path)
                self._process_extracted_files(extracted_files, result, parser_func)
            else:
                result["parsing_errors"].append(f"Unsupported file type: {file_type}")
        except Exception as e:
            result["parsing_errors"].append(f"Error processing file {file_path}: {str(e)}")
            
        return result
        
    def _process_text_file(self, file_path: str, result: Dict[str, Any], 
                           parser_func: Optional[Callable[[str], Dict[str, Any]]]) -> None:
        """
        Process a text file.
        
        Args:
            file_path: Path to the text file
            result: Result dictionary to update
            parser_func: Optional function to parse text content
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
                
            # Use parser function if provided
            if parser_func and callable(parser_func):
                parsed = parser_func(text)
                self._merge_results(result, parsed)
        except Exception as e:
            result["parsing_errors"].append(f"Error processing text file {file_path}: {str(e)}")
            
    def _process_json_file(self, file_path: str, result: Dict[str, Any],
                           parser_func: Optional[Callable[[str], Dict[str, Any]]]) -> None:
        """
        Process a JSON file.
        
        Args:
            file_path: Path to the JSON file
            result: Result dictionary to update
            parser_func: Optional function to parse text content
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                try:
                    data = json.load(f)
                    
                    # Extract credentials if present in expected format
                    if isinstance(data, dict):
                        if "credentials" in data and isinstance(data["credentials"], list):
                            result["credentials"].extend(data["credentials"])
                            
                        if "cookies" in data and isinstance(data["cookies"], list):
                            result["cookies"].extend(data["cookies"])
                            
                        if "system_info" in data and isinstance(data["system_info"], dict):
                            result["system_info"].update(data["system_info"])
                            
                        if "crypto_wallets" in data and isinstance(data["crypto_wallets"], list):
                            result["crypto_wallets"].extend(data["crypto_wallets"])
                            
                        if "credit_cards" in data and isinstance(data["credit_cards"], list):
                            result["credit_cards"].extend(data["credit_cards"])
                except json.JSONDecodeError:
                    # If JSON parsing fails, try as text with parser function
                    if parser_func and callable(parser_func):
                        f.seek(0)
                        text = f.read()
                        parsed = parser_func(text)
                        self._merge_results(result, parsed)
        except Exception as e:
            result["parsing_errors"].append(f"Error processing JSON file {file_path}: {str(e)}")
            
    def _process_csv_file(self, file_path: str, result: Dict[str, Any]) -> None:
        """
        Process a CSV file.
        
        Args:
            file_path: Path to the CSV file
            result: Result dictionary to update
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                reader = csv.reader(f)
                headers = next(reader, None)
                
                if not headers:
                    result["parsing_errors"].append(f"CSV file {file_path} has no headers")
                    return
                    
                # Map headers to credential fields
                username_idx = None
                password_idx = None
                domain_idx = None
                url_idx = None
                
                for i, header in enumerate(headers):
                    header_lower = header.lower()
                    if any(term in header_lower for term in ['email', 'username', 'user', 'login']):
                        username_idx = i
                    elif any(term in header_lower for term in ['password', 'pwd', 'pass']):
                        password_idx = i
                    elif any(term in header_lower for term in ['domain', 'site', 'host']):
                        domain_idx = i
                    elif any(term in header_lower for term in ['url', 'link', 'website']):
                        url_idx = i
                        
                # Process rows if we have credential columns
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
                                
                                # Add domain/URL if available
                                if domain_idx is not None and len(row) > domain_idx:
                                    credential["domain"] = row[domain_idx].strip()
                                if url_idx is not None and len(row) > url_idx:
                                    credential["url"] = row[url_idx].strip()
                                    
                                result["credentials"].append(credential)
        except Exception as e:
            result["parsing_errors"].append(f"Error processing CSV file {file_path}: {str(e)}")
            
    def _process_extracted_files(self, file_paths: List[str], result: Dict[str, Any],
                                parser_func: Optional[Callable[[str], Dict[str, Any]]]) -> None:
        """
        Process multiple extracted files.
        
        Args:
            file_paths: List of file paths
            result: Result dictionary to update
            parser_func: Optional function to parse text content
        """
        for file_path in file_paths:
            # Skip processing if already too large
            if os.path.getsize(file_path) > self.max_size_bytes:
                continue
                
            # Process each file and merge results
            file_result = self.process_file(file_path, parser_func)
            self._merge_results(result, file_result)
            
    def _merge_results(self, target: Dict[str, Any], source: Dict[str, Any]) -> None:
        """
        Merge extraction results.
        
        Args:
            target: Target dictionary to update
            source: Source dictionary with data to merge
        """
        # Merge list fields
        for key in ["credentials", "cookies", "crypto_wallets", "file_paths", 
                   "credit_cards", "parsing_errors"]:
            if key in source and source[key]:
                target[key].extend(source[key])
                
        # Merge dictionary fields
        if "system_info" in source and source["system_info"]:
            target["system_info"].update(source["system_info"])
            
    def cleanup(self) -> None:
        """Clean up temporary files and directories."""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.error(f"Error cleaning up temporary directory: {str(e)}")
            
    def __del__(self):
        """Ensure cleanup on object destruction."""
        self.executor.shutdown(wait=False)
        self.cleanup()