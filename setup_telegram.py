#!/usr/bin/env python3
"""
Setup script for Telegram authentication.
Creates a reusable session file for the Bot-Command application.
"""

import asyncio
import logging
import os
import sys
from getpass import getpass

from telethon import TelegramClient
from telethon.errors import SessionPasswordNeededError
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def setup_telegram():
    """Interactive setup for Telegram authentication."""
    # Load environment variables
    load_dotenv()
    
    # Get API credentials from environment
    api_id = os.getenv("TELEGRAM_API_ID")
    api_hash = os.getenv("TELEGRAM_API_HASH")
    session_name = os.getenv("TELEGRAM_SESSION_NAME", "bot_monitor_session")
    
    if not api_id or not api_hash:
        logger.error("TELEGRAM_API_ID and TELEGRAM_API_HASH must be set in .env file")
        sys.exit(1)
        
    # Convert api_id to int
    api_id = int(api_id)
    
    # Get phone number from user
    phone = input("Please enter your phone number (international format, e.g., +1234567890): ")
    
    # Create the client and connect
    client = TelegramClient(session_name, api_id, api_hash)
    
    try:
        logger.info("Starting Telegram client...")
        await client.connect()
        
        if not await client.is_user_authorized():
            logger.info("Sending code request...")
            await client.send_code_request(phone)
            
            code = input("Enter the code you received: ")
            try:
                await client.sign_in(phone, code)
            except SessionPasswordNeededError:
                # 2FA is enabled
                password = getpass("Two-step verification is enabled. Please enter your password: ")
                await client.sign_in(password=password)
                
        logger.info(f"Successfully authenticated! Session file saved as {session_name}.session")
        logger.info("You can now run the main application.")
        
    except Exception as e:
        logger.error(f"Error during setup: {str(e)}")
        sys.exit(1)
    finally:
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(setup_telegram()) 