"""
Tests for the Azorult stealer parser plugin.
"""

import unittest
import os
import tempfile
import json
from src.processing.message_parser import MessageParser
from src.processing.stealer_plugins.azorult import AzorultParser

class TestAzorultParser(unittest.TestCase):
    """Tests for AzorultParser class."""
    
    def setUp(self):
        """Set up test environment."""
        self.parser = AzorultParser()
        self.full_parser = MessageParser()
        
    def test_initialization(self):
        """Test parser initialization."""
        self.assertIsNotNone(self.parser)
        self.assertEqual(self.parser.name, "azorult_parser")
        self.assertEqual(self.parser.value_multiplier, 1.35)
        
    def test_azorult_detection(self):
        """Test Azorult stealer format detection."""
        # Test messages with varying levels of confidence
        high_confidence_message = {
            "text": "AZORult Stealer Report\n[SYSTEM]\nOS: Windows 10\nUSER: test_user\n",
            "bot_id": "test_bot",
            "message_id": "123"
        }
        
        medium_confidence_message = {
            "text": "[DATA]\nURL: example.com\nLOGIN: user\nPASSWORD: pass123\n",
            "bot_id": "test_bot",
            "message_id": "456"
        }
        
        low_confidence_message = {
            "text": "IP: 192.168.1.1\nUSER: user1\n",
            "bot_id": "test_bot",
            "message_id": "789"
        }
        
        unrelated_message = {
            "text": "This is not an Azorult message.",
            "bot_id": "test_bot",
            "message_id": "012"
        }
        
        # Test detection confidence
        can_parse, confidence = self.parser.can_parse(high_confidence_message)
        self.assertTrue(can_parse)
        self.assertGreaterEqual(confidence, 0.7)
        
        can_parse, confidence = self.parser.can_parse(medium_confidence_message)
        self.assertTrue(can_parse, "Should recognize medium confidence Azorult format")
        
        can_parse, confidence = self.parser.can_parse(low_confidence_message)
        self.assertLess(confidence, self.parser.confidence_threshold)
        
        can_parse, confidence = self.parser.can_parse(unrelated_message)
        self.assertFalse(can_parse)
        self.assertLessEqual(confidence, 0.1)
        
    def test_credential_extraction(self):
        """Test extraction of credentials from Azorult format."""
        message = {
            "text": """
            AZORult Report
            [DATA]
            URL: https://example.com
            LOGIN: test_user
            PASSWORD: test_pass
            
            HOST: banking.com
            USER: bank_user
            PASS: secure_pass
            
            SOFTWARE: FileZilla
            USER: ftp_user
            PASS: ftp_pass123
            """,
            "bot_id": "test_bot",
            "message_id": "123"
        }
        
        result = self.parser.parse(message)
        
        # Check credential extraction
        self.assertIn("credentials", result)
        self.assertEqual(len(result["credentials"]), 3)
        
        # Check specific credential elements
        example_cred = next((c for c in result["credentials"] if c.get("domain") == "example.com"), None)
        self.assertIsNotNone(example_cred)
        self.assertEqual(example_cred["username"], "test_user")
        self.assertEqual(example_cred["password"], "test_pass")
        
        banking_cred = next((c for c in result["credentials"] if c.get("domain") == "banking.com"), None)
        self.assertIsNotNone(banking_cred)
        self.assertEqual(banking_cred["username"], "bank_user")
        
    def test_system_info_extraction(self):
        """Test extraction of system information from Azorult format."""
        message = {
            "text": """
            AZORult Stealer Report
            [SYSTEM]
            OS: Windows 10 Enterprise
            PC-NAME: CORP-PC001
            USERNAME: john.smith
            IP: 192.168.10.50
            COUNTRY: United States
            RESOLUTION: 1920x1080
            ANTIVIRUS: Symantec Endpoint Protection
            """,
            "bot_id": "test_bot",
            "message_id": "123"
        }
        
        result = self.parser.parse(message)
        
        # Check system info extraction
        self.assertIn("system_info", result)
        system_info = result["system_info"]
        
        self.assertEqual(system_info.get("os"), "Windows 10 Enterprise")
        self.assertEqual(system_info.get("computer_name"), "CORP-PC001")
        self.assertEqual(system_info.get("username"), "john.smith")
        self.assertEqual(system_info.get("ip"), "192.168.10.50")
        self.assertEqual(system_info.get("country"), "United States")
        self.assertEqual(system_info.get("screen_resolution"), "1920x1080")
        self.assertEqual(system_info.get("antivirus"), "Symantec Endpoint Protection")
        
        # Check enterprise detection
        self.assertTrue(system_info.get("is_corporate", False))
        
    def test_credit_card_extraction(self):
        """Test extraction of credit card information from Azorult format."""
        message = {
            "text": """
            AZORult Report
            [CARDS]
            CARD NUMBER: 4111 1111 1111 1111
            EXPIRY: 12/25
            CVV: 123
            
            CARD-NUMBER: 5500 0000 0000 0004
            EXP: 10/24
            CVV: 456
            CARD-HOLDER: John Smith
            """,
            "bot_id": "test_bot",
            "message_id": "123"
        }
        
        result = self.parser.parse(message)
        
        # Check credit card extraction
        self.assertIn("credit_cards", result)
        self.assertEqual(len(result["credit_cards"]), 2)
        
        # Check specific credit card details
        visa_card = next((c for c in result["credit_cards"] if c.get("number") == "4111111111111111"), None)
        self.assertIsNotNone(visa_card)
        self.assertEqual(visa_card["expiry"], "12/25")
        self.assertEqual(visa_card["cvv"], "123")
        
        master_card = next((c for c in result["credit_cards"] if c.get("number") == "5500000000000004"), None)
        self.assertIsNotNone(master_card)
        self.assertEqual(master_card["holder"], "John Smith")
        
    def test_crypto_wallet_extraction(self):
        """Test extraction of crypto wallet information from Azorult format."""
        message = {
            "text": """
            AZORult Report
            [WALLETS]
            BITCOIN WALLET: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
            ETHEREUM WALLET: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
            SEED PHRASE: word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
            """,
            "bot_id": "test_bot",
            "message_id": "123"
        }
        
        result = self.parser.parse(message)
        
        # Check wallet extraction
        self.assertIn("crypto_wallets", result)
        self.assertEqual(len(result["crypto_wallets"]), 3)
        
        # Check specific wallet details
        bitcoin_wallet = next((w for w in result["crypto_wallets"] if w.get("type") == "bitcoin"), None)
        self.assertIsNotNone(bitcoin_wallet)
        self.assertEqual(bitcoin_wallet["value"], "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
        
        ethereum_wallet = next((w for w in result["crypto_wallets"] if w.get("type") == "ethereum"), None)
        self.assertIsNotNone(ethereum_wallet)
        
        seed_phrase = next((w for w in result["crypto_wallets"] if w.get("is_seed_phrase") is True), None)
        self.assertIsNotNone(seed_phrase)
        
    def test_file_parsing(self):
        """Test parsing of Azorult log files."""
        # Create a temporary JSON file with Azorult data
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w') as f:
            json.dump({
                "system": {
                    "OS": "Windows 10",
                    "ComputerName": "TEST-PC",
                    "UserName": "test_user",
                    "IP": "192.168.1.100"
                },
                "credentials": [
                    {
                        "url": "https://example.com",
                        "Username": "file_user",
                        "Password": "file_pass"
                    }
                ],
                "cards": [
                    {
                        "Number": "4111111111111111",
                        "Expiry": "12/25",
                        "CVV": "123"
                    }
                ]
            }, f)
            temp_file = f.name
            
        try:
            # Test file parsing
            file_result = self.parser.parse_file(temp_file)
            
            # Check basic structure
            self.assertIn("credentials", file_result)
            self.assertIn("system_info", file_result)
            self.assertIn("credit_cards", file_result)
            
            # Check credential extraction
            self.assertEqual(len(file_result["credentials"]), 1)
            self.assertEqual(file_result["credentials"][0]["username"], "file_user")
            
            # Check system info extraction
            self.assertEqual(file_result["system_info"].get("os"), "Windows 10")
            
            # Check credit card extraction
            self.assertEqual(len(file_result["credit_cards"]), 1)
            self.assertEqual(file_result["credit_cards"][0]["number"], "4111111111111111")
            
        finally:
            # Clean up temporary file
            os.unlink(temp_file)
            
    def test_integration_with_message_parser(self):
        """Test integration of Azorult parser with the main MessageParser."""
        # Create message with Azorult format
        message = {
            "text": """
            AZORult Report 2.0
            [SYSTEM]
            OS: Windows 10
            PC-NAME: HOME-PC
            USERNAME: user
            IP: 192.168.1.100
            
            [DATA]
            URL: https://example.com
            LOGIN: example_user
            PASSWORD: example_pass
            """,
            "bot_id": "azorult_bot",
            "bot_username": "azorult_bot_user",
            "message_id": "123"
        }
        
        # Parse with the main message parser
        result = self.full_parser.parse_message(message)
        
        # Check that Azorult parser was selected
        self.assertIn("credentials", result)
        self.assertEqual(len(result["credentials"]), 1)
        
        # Check that correct values were extracted
        self.assertEqual(result["credentials"][0]["username"], "example_user")
        self.assertEqual(result["credentials"][0]["password"], "example_pass")
        
        # Check system info
        self.assertIn("system_info", result)
        self.assertEqual(result["system_info"].get("os"), "Windows 10")
        
        # Check value score calculation
        self.assertIn("value_score", result)
        self.assertGreater(result["value_score"], 0)
    
    def test_value_scoring(self):
        """Test value scoring logic specific to Azorult."""
        # Create message with high value assets
        high_value_message = {
            "text": """
            AZORult Report
            [SYSTEM]
            OS: Windows 10 Enterprise
            PC-NAME: CORP-PC
            USERNAME: admin.user
            
            [DATA]
            URL: https://bank.com
            LOGIN: bank_user
            PASSWORD: bank_pass
            
            [CARDS]
            CARD NUMBER: 4111 1111 1111 1111
            EXPIRY: 12/25
            CVV: 123
            CARD-HOLDER: John Smith
            
            [CRYPTO]
            BITCOIN WALLET: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
            SEED PHRASE: word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12
            """,
            "bot_id": "test_bot",
            "message_id": "123"
        }
        
        # Create message with lower value assets
        low_value_message = {
            "text": """
            AZORult Report
            [SYSTEM]
            OS: Windows 10 Home
            PC-NAME: HOME-PC
            USERNAME: home_user
            
            [DATA]
            URL: https://socialsite.com
            LOGIN: social_user
            PASSWORD: social_pass
            """,
            "bot_id": "test_bot",
            "message_id": "456"
        }
        
        high_result = self.parser.parse(high_value_message)
        low_result = self.parser.parse(low_value_message)
        
        # High value message should have significantly higher score
        self.assertGreater(high_result["value_score"], low_result["value_score"])
        self.assertGreater(high_result["value_score"], 70)  # Should be a high value score


if __name__ == '__main__':
    unittest.main()
