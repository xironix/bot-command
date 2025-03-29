"""
Test the JSON-first parsing approach in the MessageParser.
"""

import unittest
from unittest.mock import patch
import json

from src.processing.message_parser import MessageParser

class TestJsonParsing(unittest.TestCase):
    """Tests for the JSON-first parsing capability."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a mock for the plugins to avoid dependencies
        self.mock_plugins = []
        with patch('src.processing.stealer_plugins.AVAILABLE_PLUGINS', self.mock_plugins):
            self.parser = MessageParser()
        
    def test_json_pattern_detection(self):
        """Test that JSON patterns are correctly detected."""
        # Verify JSON patterns were initialized
        self.assertTrue(hasattr(self.parser, '_json_patterns'))
        self.assertTrue(len(self.parser._json_patterns) > 0)
        
        # Test valid JSON detection
        valid_json_text = '{"credentials": [{"username": "test@example.com", "password": "password123"}]}'
        for pattern in self.parser._json_patterns:
            self.assertTrue(pattern.search(valid_json_text))
            
        # Test invalid text
        invalid_text = "This is not JSON at all."
        for pattern in self.parser._json_patterns:
            self.assertFalse(pattern.search(invalid_text))
            
    def test_parse_json_message(self):
        """Test parsing a message with JSON content."""
        # Create a sample JSON message
        json_data = {
            "system_info": {
                "os": "Windows 10",
                "hardware_id": "ABC123",
                "username": "JohnDoe"
            },
            "credentials": [
                {
                    "username": "user@example.com",
                    "password": "secret123",
                    "domain": "example.com"
                }
            ]
        }
        
        message_data = {
            "text": json.dumps(json_data),
            "bot_id": 12345,
            "bot_username": "test_bot",
            "message_id": 67890,
            "has_media": False
        }
        
        # Parse the message
        result = self.parser.parse_message(message_data)
        
        # Verify the parsing was successful
        self.assertEqual(len(result["credentials"]), 1)
        self.assertIn("os", result["system_info"])
        self.assertEqual(result["system_info"]["os"], "Windows 10")
        self.assertEqual(result["credentials"][0]["username"], "user@example.com")
        
    def test_partial_json_extraction(self):
        """Test extracting JSON from a message with mixed content."""
        # Create a message with JSON embedded within other text
        message_text = (
            "Stealer Bot Report\n"
            "==================\n"
            "Victim ID: 12345\n"
            "JSON DATA:\n"
            '{"system_info": {"os": "Windows 11", "hardware_id": "XYZ789"}, '
            '"credentials": [{"username": "admin@company.com", "password": "p@ss"}]}\n'
            "End of report."
        )
        
        message_data = {
            "text": message_text,
            "bot_id": 12345,
            "bot_username": "test_bot",
            "message_id": 67890,
            "has_media": False
        }
        
        # Parse the message
        result = self.parser.parse_message(message_data)
        
        # Verify the embedded JSON was successfully extracted and parsed
        self.assertEqual(len(result["credentials"]), 1)
        self.assertIn("os", result["system_info"])
        self.assertEqual(result["system_info"]["os"], "Windows 11")
        self.assertEqual(result["credentials"][0]["username"], "admin@company.com")
        
    def test_extract_domain_from_username(self):
        """Test the domain extraction from email usernames."""
        self.assertEqual(self.parser._extract_domain_from_username("user@example.com"), "example.com")
        self.assertIsNone(self.parser._extract_domain_from_username("justusername"))
        self.assertIsNone(self.parser._extract_domain_from_username(None))
        
if __name__ == "__main__":
    unittest.main()
