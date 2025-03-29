"""
Tests for the message parser module.
"""

import unittest
import os
import tempfile
import json
from unittest.mock import patch, MagicMock
from src.processing.message_parser import MessageParser
from src.processing.stealer_plugins.base import StealerParserPlugin
from src.processing.stealer_plugins import (
    RedLineParser,
    RiseProParser, 
    LummaParser,
    StealCParser,
    SnakeStealerParser
)

class TestMessageParser(unittest.TestCase):
    """Tests for MessageParser class."""
    
    def setUp(self):
        """Set up test environment."""
        self.parser = MessageParser()
        
    def test_initialization(self):
        """Test parser initialization."""
        self.assertIsNotNone(self.parser)
        self.assertIsInstance(self.parser.plugins, list)
        self.assertTrue(len(self.parser.plugins) > 0)  # Plugins should be loaded
        
    def test_plugin_loading(self):
        """Test plugin loading."""
        # Verify that plugins are properly loaded
        plugin_types = [type(plugin) for plugin in self.parser.plugins]
        
        # Check for expected plugin types
        self.assertIn(RedLineParser, plugin_types)
        self.assertIn(RiseProParser, plugin_types)
        self.assertIn(LummaParser, plugin_types)
        self.assertIn(StealCParser, plugin_types)
        self.assertIn(SnakeStealerParser, plugin_types)
        
        # All plugins should inherit from the base class
        for plugin in self.parser.plugins:
            self.assertIsInstance(plugin, StealerParserPlugin)
            
    def test_fallback_parsing(self):
        """Test fallback parsing with generic patterns."""
        # Test message with generic credential format
        message = {
            "text": """
            Website: example.com
            Username: testuser
            Password: testpass123
            """,
            "bot_id": "test_bot",
            "bot_username": "test_bot_user",
            "message_id": "123"
        }
        
        result = self.parser.parse_message(message)
        
        # Check basic structure
        self.assertIn("credentials", result)
        self.assertIn("cookies", result)
        self.assertIn("system_info", result)
        
        # Check credential extraction
        self.assertEqual(len(result["credentials"]), 1)
        self.assertEqual(result["credentials"][0]["username"], "testuser")
        self.assertEqual(result["credentials"][0]["password"], "testpass123")
        self.assertEqual(result["credentials"][0]["domain"], "example.com")
        
    def test_redline_parsing(self):
        """Test RedLine stealer format parsing."""
        # Mock RedLine format
        message = {
            "text": """
            RedLine Stealer Report
            =====System Info=====
            OS: Windows 10 Pro
            HWID: 1234567890
            Computer Name: DESKTOP-TEST
            User: TestUser
            Local IP: 192.168.1.100
            IP: 203.0.113.1
            
            =====Browser=====
            URL: https://example.com
            Username: redline_user
            Password: redline_pass
            
            URL: https://bank.com
            Username: bank_user
            Password: bank_pass123
            
            =====Crypto=====
            Bitcoin Core: C:\\Users\\TestUser\\wallet.dat
            """,
            "bot_id": "redline_bot",
            "bot_username": "redline_bot_user",
            "message_id": "456"
        }
        
        result = self.parser.parse_message(message)
        
        # Check for RedLine specific parsing
        self.assertIn("credentials", result)
        self.assertGreaterEqual(len(result["credentials"]), 2)
        
        # Check for proper domain extraction
        bank_cred = next((c for c in result["credentials"] if c.get("domain") == "bank.com"), None)
        self.assertIsNotNone(bank_cred)
        self.assertEqual(bank_cred["username"], "bank_user")
        
        # Check for crypto wallet extraction
        self.assertIn("crypto_wallets", result)
        self.assertGreaterEqual(len(result.get("crypto_wallets", [])), 1)
        
        # Check system info
        self.assertIn("system_info", result)
        self.assertEqual(result["system_info"].get("os"), "Windows 10 Pro")
        
        # Check for value score
        self.assertIn("value_score", result)
        self.assertGreater(result["value_score"], 0)
        
    def test_lumma_parsing(self):
        """Test Lumma stealer format parsing."""
        # Mock Lumma format
        message = {
            "text": """
            LummaC2 Stealer Log
            --System Info--
            OS: Windows 11 Enterprise
            Computer Name: CORP-LAPTOP
            Username: corp_user
            HWID: ABCDEF123456
            Local IP: 192.168.10.50
            IP Address: 198.51.100.1
            Country: United States
            Language: en-US
            Antivirus: Windows Defender
            
            --Browser Data--
            Domain: bank.example.com
            Username: finance_user
            Password: secure_finance_pass
            
            Domain: mail.example.com
            Cookie: auth_token=ABCDEF123456; Expires: 2025-01-01
            
            --Crypto Wallets--
            MetaMask: C:\\Users\\corp_user\\metamask_wallet.json
            Private Key: 0xABCDEF123456789
            
            2FA Backup Codes: 123456, 789012, 345678
            
            Session Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
            """,
            "bot_id": "lumma_bot",
            "bot_username": "lumma_bot_user",
            "message_id": "789"
        }
        
        result = self.parser.parse_message(message)
        
        # Check for Lumma specific parsing
        self.assertIn("credentials", result)
        self.assertGreaterEqual(len(result["credentials"]), 1)
        
        # Check for cookie with expiry
        self.assertIn("cookies", result)
        self.assertGreaterEqual(len(result["cookies"]), 1)
        cookie = result["cookies"][0]
        self.assertEqual(cookie.get("domain"), "mail.example.com")
        self.assertTrue("can_regenerate" in cookie and cookie["can_regenerate"])
        
        # Check for 2FA codes
        self.assertIn("two_factor_codes", result)
        
        # Check for session token
        self.assertIn("session_tokens", result)
        
        # Check system info with corporate marker
        self.assertIn("system_info", result)
        self.assertEqual(result["system_info"].get("os"), "Windows 11 Enterprise")
        self.assertTrue(result["system_info"].get("is_corporate", False))
        
        # Check for value score
        self.assertIn("value_score", result)
        self.assertGreater(result["value_score"], 0)
        
    def test_risepro_parsing(self):
        """Test RisePro stealer format parsing."""
        # Mock RisePro format
        message = {
            "text": """
            RisePro Stealer Report
            ====System====
            OS: Windows 10 Home
            Computer Name: HOME-PC
            Username: home_user
            Country: Canada
            IP: 203.0.113.10
            
            ====Browsers====
            URL: https://shopping.example.com
            Username: shopper123
            Password: shop_pass456
            
            ====Cards====
            Card Number: 4111111111111111
            Expiry: 12/25
            CVV: 123
            Name: John Doe
            
            ====Telegram====
            Telegram Session: C:\\Users\\home_user\\AppData\\Roaming\\Telegram Desktop\\tdata
            
            ====Discord====
            Discord Token: MTAxNDIzMjYxOTk3NTY3Mzg2MA.G6lnZt.owDkCjLqLJ2C5d24Q4
            """,
            "bot_id": "risepro_bot",
            "bot_username": "risepro_bot_user",
            "message_id": "101112"
        }
        
        result = self.parser.parse_message(message)
        
        # Check for RisePro specific parsing
        self.assertIn("credentials", result)
        self.assertGreaterEqual(len(result["credentials"]), 1)
        
        # Check for credit card data
        self.assertIn("credit_cards", result)
        self.assertGreaterEqual(len(result["credit_cards"]), 1)
        card = result["credit_cards"][0]
        self.assertEqual(card.get("number"), "4111111111111111")
        self.assertEqual(card.get("cvv"), "123")
        
        # Check for messenger tokens
        self.assertIn("messenger_tokens", result)
        self.assertGreaterEqual(len(result["messenger_tokens"]), 2)
        discord_token = next((t for t in result["messenger_tokens"] if t.get("type") == "discord"), None)
        self.assertIsNotNone(discord_token)
        
        # Check system info
        self.assertIn("system_info", result)
        self.assertEqual(result["system_info"].get("country"), "Canada")
        
        # Check for value score
        self.assertIn("value_score", result)
        self.assertGreater(result["value_score"], 0)
        
    def test_stealc_parsing(self):
        """Test StealC stealer format parsing."""
        # Mock StealC format
        message = {
            "text": """
            StealC Log
            [System Info]
            OS: Windows 10 Pro
            Computer: DESKTOP-USER1
            Username: regular_user
            IP: 192.0.2.100
            
            [Browser]
            Host: mail.example.org
            Username: mail_user
            Password: mail_pass_123
            
            Host: forum.example.org
            Cookie: session=ABCDEF123456
            
            [Games]
            Game: Steam
            Username: gamer123
            Password: game_pass_456
            
            [Wallets]
            Bitcoin: C:\\Users\\regular_user\\bitcoin_wallet.dat
            """,
            "bot_id": "stealc_bot",
            "bot_username": "stealc_bot_user",
            "message_id": "131415"
        }
        
        result = self.parser.parse_message(message)
        
        # Check for StealC specific parsing
        self.assertIn("credentials", result)
        self.assertGreaterEqual(len(result["credentials"]), 1)
        
        # Check for gaming credentials
        self.assertIn("game_credentials", result)
        self.assertGreaterEqual(len(result["game_credentials"]), 1)
        game_cred = result["game_credentials"][0]
        self.assertEqual(game_cred.get("game"), "Steam")
        
        # Check for cookies
        self.assertIn("cookies", result)
        self.assertGreaterEqual(len(result["cookies"]), 1)
        
        # Check for crypto wallets
        self.assertIn("crypto_wallets", result)
        self.assertGreaterEqual(len(result["crypto_wallets"]), 1)
        
        # Check system info
        self.assertIn("system_info", result)
        self.assertEqual(result["system_info"].get("username"), "regular_user")
        
        # Check for value score
        self.assertIn("value_score", result)
        self.assertGreater(result["value_score"], 0)
        
    def test_snake_stealer_parsing(self):
        """Test SnakeStealer format parsing."""
        # Mock SnakeStealer format (JSON-based)
        message = {
            "text": """
            {
              "system": {
                "os": "Windows 10 Enterprise",
                "computerName": "CORP-WORKSTATION",
                "username": "corp.user",
                "hwid": "ABCDEF123456",
                "ip": "198.51.100.100",
                "country": "United States",
                "isDomainJoined": true,
                "isVirtualMachine": false
              },
              "credentials": [
                {
                  "url": "https://corporate.example.com",
                  "username": "admin.user",
                  "password": "corp_admin_pass"
                },
                {
                  "domain": "mail.example.com",
                  "username": "email.user",
                  "password": "email_pass_123"
                }
              ],
              "ssoTokens": [
                {
                  "provider": "Azure AD",
                  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
                }
              ]
            }
            """,
            "bot_id": "snake_bot",
            "bot_username": "snake_bot_user",
            "message_id": "161718"
        }
        
        result = self.parser.parse_message(message)
        
        # Check for SnakeStealer specific parsing
        self.assertIn("credentials", result)
        self.assertGreaterEqual(len(result["credentials"]), 2)
        
        # Check for SSO tokens
        self.assertIn("sso_tokens", result)
        self.assertGreaterEqual(len(result["sso_tokens"]), 1)
        
        # Check system info with corporate markers
        self.assertIn("system_info", result)
        self.assertEqual(result["system_info"].get("os"), "Windows 10 Enterprise")
        self.assertTrue(result["system_info"].get("is_corporate", False))
        self.assertTrue(result["system_info"].get("is_domain_joined", False))
        
        # Check for value score with corporate bonus
        self.assertIn("value_score", result)
        self.assertGreater(result["value_score"], 0)
        
    def test_file_parsing(self):
        """Test file parsing."""
        # Create a temporary JSON file
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
            json.dump({
                "credentials": [
                    {
                        "URL": "https://example.com",
                        "Username": "file_user",
                        "Password": "file_pass"
                    }
                ],
                "system": {
                    "OS": "Windows 11",
                    "ComputerName": "LAPTOP-TEST"
                }
            }, f)
            temp_file = f.name
            
        try:
            # Mock message with media attachment
            message = {
                "text": "Attached file",
                "bot_id": "file_bot",
                "bot_username": "file_bot_user",
                "message_id": "192021",
                "has_media": True,
                "media_path": temp_file
            }
            
            result = self.parser.parse_message(message)
            
            # Check file parsing results
            self.assertIn("credentials", result)
            self.assertGreaterEqual(len(result["credentials"]), 1)
            
            cred = result["credentials"][0]
            self.assertEqual(cred.get("username"), "file_user")
            self.assertEqual(cred.get("password"), "file_pass")
            
            # Check system info from file
            self.assertIn("system_info", result)
            self.assertEqual(result["system_info"].get("os"), "Windows 11")
        finally:
            # Clean up temporary file
            os.unlink(temp_file)
            
    def test_value_scoring(self):
        """Test value scoring logic."""
        # High-value message (financial credentials)
        high_value_message = {
            "text": """
            URL: https://bank.com
            Username: bank_user
            Password: bank_pass123
            
            Card Number: 4111111111111111
            Expiry: 12/25
            CVV: 123
            """,
            "bot_id": "high_value_bot",
            "bot_username": "high_value_bot_user",
            "message_id": "222324"
        }
        
        high_result = self.parser.parse_message(high_value_message)
        
        # Low-value message (social media credentials)
        low_value_message = {
            "text": """
            URL: https://socialsite.com
            Username: social_user
            Password: social_pass123
            """,
            "bot_id": "low_value_bot",
            "bot_username": "low_value_bot_user",
            "message_id": "252627"
        }
        
        low_result = self.parser.parse_message(low_value_message)
        
        # High-value message should have higher score than low-value message
        self.assertGreater(high_result["value_score"], low_result["value_score"])


if __name__ == '__main__':
    unittest.main()
