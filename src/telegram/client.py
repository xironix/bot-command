"""
Telegram client module for silently monitoring stealer bots.

This module handles the connection to Telegram's API and intercepts messages
without modifying the original bot's behavior.
"""

import asyncio
import logging
import os
import shutil
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Any, Optional, Union, Set

from telethon import TelegramClient, events
from telethon.tl import types
from telethon.errors import SessionPasswordNeededError, PhoneCodeInvalidError

from config.settings import config

logger = logging.getLogger(__name__)

class TelegramMonitor:
    """Silent monitor for Telegram bots."""
    
    def __init__(self, message_handler: Callable[[Dict[str, Any]], None]):
        """
        Initialize Telegram monitor.
        
        Args:
            message_handler: Callback function to handle intercepted messages
        """
        self.config = config.telegram
        self.message_handler = message_handler
        self.clients = {}  # Store multiple clients for different bots
        self._main_client = None  # Main user client for monitoring
        
        # Media file management
        self.downloads_dir = os.path.abspath("downloads")
        self.tracked_downloads = set()  # Set of downloaded files being tracked
        self.media_retention_days = int(os.getenv("MEDIA_RETENTION_DAYS", "30"))
        self.max_disk_usage_gb = float(os.getenv("MAX_DISK_USAGE_GB", "10"))
        
        # Create downloads directory if it doesn't exist
        os.makedirs(self.downloads_dir, exist_ok=True)
        
    async def initialize(self):
        """Initialize Telegram clients and connections."""
        # Set up main user client for monitoring bot messages
        self._main_client = TelegramClient(
            self.config.session_name,
            self.config.api_id,
            self.config.api_hash
        )
        
        await self._main_client.start()
        logger.info("Main Telegram client initialized")
        
        # Set up event handlers
        self._setup_event_handlers()
        
        # Schedule cleanup tasks
        asyncio.create_task(self._schedule_media_cleanup())
        
        # Clean up any leftover files from previous runs
        await self._cleanup_old_downloads()
        
    async def _ensure_logged_in(self):
        """Ensure the client is logged in."""
        if not await self._main_client.is_user_authorized():
            logger.info("User not authorized, proceeding with login")
            
            if not self.config.phone_number:
                raise ValueError("Phone number is required for Telegram login")
                
            await self._main_client.send_code_request(self.config.phone_number)
            
            # This will require user interaction in a production environment
            # For automated environments, this could be handled via environment variables
            code = input("Enter the code you received: ")
            
            try:
                await self._main_client.sign_in(self.config.phone_number, code)
            except SessionPasswordNeededError:
                # 2FA enabled
                password = input("Enter your 2FA password: ")
                await self._main_client.sign_in(password=password)
    
    def _setup_event_handlers(self):
        """Set up event handlers for capturing messages."""
        
        # Monitor messages from bots that we're tracking
        @self._main_client.on(events.NewMessage)
        async def message_handler(event):
            # Check if the message is from a bot we're interested in
            if hasattr(event.message.peer_id, 'user_id'):
                sender = await self._main_client.get_entity(event.message.peer_id)
                
                # Process if it's a bot and we're tracking it
                if sender.bot and sender.username:
                    # Check if this bot is in our monitoring list
                    # This could be enhanced to check against a database of tracked bots
                    if await self._should_process_bot(sender.username):
                        await self._process_message(event.message, sender)
                        
    async def _should_process_bot(self, username: str) -> bool:
        """
        Determine if a bot should be processed.
        
        Args:
            username: Bot's username
            
        Returns:
            True if the bot should be processed, False otherwise
        """
        try:
            # Check blocklist first - if bot is blocklisted, never process it
            if username in self.config.bot_blocklist:
                logger.debug(f"Bot {username} is in blocklist, ignoring")
                return False
                
            # Check explicit allowlist
            if username in self.config.bot_usernames:
                logger.debug(f"Bot {username} is in allowlist, processing")
                return True
                
            # Check if bot token matches
            if username in self.config.bot_tokens:
                logger.debug(f"Bot {username} matches a configured token, processing")
                return True
                
            # If monitor_all_bots is enabled, process everything not blocklisted
            if self.config.monitor_all_bots:
                logger.debug(f"Processing bot {username} (monitor_all_bots=True)")
                return True
                
            # If filtering by patterns is enabled, check patterns
            if self.config.filter_by_patterns:
                # Check for known stealer bot patterns
                stealer_patterns = [
                    # Common stealer bot naming patterns
                    r"steal(er)?bot",
                    r"info(rmation)?collect(or)?",
                    r"data(collect(or)?|grab(ber)?)",
                    r"cred(ential)?s?(grab(ber)?|collect(or)?)",
                    r"log(ger|collect(or)?)",
                    r"(cookie|cred)s?dump(er)?",
                    r"exfil(trat(e|or|ion))?",
                    r"grab(ber)?bot",
                    r"harvest(er)?bot",
                    r"redline(steal(er)?)?",
                    r"raccoon(steal(er)?)?",
                    r"vidar(steal(er)?)?",
                    r"azorult",
                    r"loki(steal(er)?)?",
                    r"taurus(steal(er)?)?",
                    r"(meteor|meta)steal(er)?",
                    r"blackguard",
                    r"mars(steal(er)?)?",
                    r"titan(steal(er)?)?",
                    r"aurora(steal(er)?)?",
                ]
                
                # Check if username matches any pattern
                import re
                for pattern in stealer_patterns:
                    if re.search(pattern, username, re.IGNORECASE):
                        logger.info(f"Bot {username} matched stealer pattern {pattern}")
                        return True
            
            # Check database of known stealer bots (not implemented in this version)
            try:
                # This would be implemented by querying MongoDB in a real-world scenario
                # if await self._check_bot_in_database(username):
                #     logger.info(f"Bot {username} found in database of known stealer bots")
                #     return True
                pass
            except Exception as e:
                logger.error(f"Error checking bot database: {str(e)}")
            
            # If we reach here, bot didn't match any criteria
            logger.debug(f"Bot {username} did not match any monitoring criteria, ignoring")
            return False
            
        except Exception as e:
            logger.error(f"Error in bot filtering for {username}: {str(e)}")
            # Default to safe behavior - don't process if we can't determine
            return False
        
    async def _process_message(self, message: types.Message, sender: types.User):
        """
        Process a message from a bot.
        
        Args:
            message: Telegram message
            sender: Message sender
        """
        # Extract relevant data from the message
        data = {
            "bot_id": sender.id,
            "bot_username": sender.username,
            "message_id": message.id,
            "timestamp": datetime.utcnow(),
            "text": message.text if message.text else "",
            "has_media": message.media is not None,
            "media_type": type(message.media).__name__ if message.media else None,
            "raw_message": message.to_dict()  # Store full message for advanced processing
        }
        
        # If media is present, download it
        if message.media:
            try:
                # Download and store media
                media_path = await self._download_media(message)
                if media_path:
                    data["media_path"] = media_path
            except Exception as e:
                logger.error(f"Failed to download media: {str(e)}")
                
        # Pass to handler
        self.message_handler(data)
        
    async def _download_media(self, message: types.Message) -> Optional[str]:
        """
        Download media from a message.
        
        Args:
            message: Telegram message with media
            
        Returns:
            Path to the downloaded media or None if download failed
        """
        try:
            # Check available disk space before download
            if not self._check_disk_space():
                logger.warning("Disk space threshold exceeded, cleaning old downloads before continuing")
                await self._cleanup_old_downloads(force=True)
                
                # Check again after cleanup
                if not self._check_disk_space():
                    logger.error("Insufficient disk space even after cleanup, skipping download")
                    return None
            
            # Generate a unique filename
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"{self.downloads_dir}/{message.id}_{timestamp}"
            
            # Download the media
            path = await self._main_client.download_media(message, filename)
            
            if path:
                # Add to tracked downloads for cleanup
                self.tracked_downloads.add(path)
                logger.debug(f"Downloaded media to {path}")
            
            return path
        except Exception as e:
            logger.error(f"Failed to download media: {str(e)}")
            return None
            
    async def monitor_bot_channel(self, channel_id: Union[int, str]):
        """
        Monitor a specific bot channel.
        
        Args:
            channel_id: ID or username of the channel to monitor
        """
        try:
            # Get the channel entity
            channel = await self._main_client.get_entity(channel_id)
            logger.info(f"Started monitoring channel: {channel.title}")
            
            # We don't need to do anything more here since our event handlers
            # will catch any new messages
        except Exception as e:
            logger.error(f"Failed to monitor channel {channel_id}: {str(e)}")
            
    def _check_disk_space(self) -> bool:
        """
        Check if available disk space is above threshold.
        
        Returns:
            True if enough space is available, False otherwise
        """
        try:
            # Get disk usage of downloads directory
            total, used, free = shutil.disk_usage(self.downloads_dir)
            
            # Convert to GB
            used_gb = used / (1024 ** 3)
            total_gb = total / (1024 ** 3)
            
            # Log current usage
            logger.debug(f"Current disk usage: {used_gb:.2f}GB of {total_gb:.2f}GB")
            
            # Check if we're under the threshold
            return used_gb < self.max_disk_usage_gb
        except Exception as e:
            logger.error(f"Error checking disk space: {str(e)}")
            # Assume there's enough space if we can't check
            return True
            
    async def _cleanup_old_downloads(self, force: bool = False):
        """
        Clean up old downloaded media files.
        
        Args:
            force: If True, be more aggressive in cleanup
        """
        try:
            logger.info(f"Cleaning up old downloaded media files{' (forced)' if force else ''}")
            
            # Get current time
            now = datetime.utcnow()
            
            # Adjust retention period for forced cleanup
            retention_days = 1 if force else self.media_retention_days
            cutoff_time = now - timedelta(days=retention_days)
            
            # List all files in downloads directory
            if os.path.exists(self.downloads_dir):
                files = os.listdir(self.downloads_dir)
                deleted_count = 0
                
                for file in files:
                    file_path = os.path.join(self.downloads_dir, file)
                    
                    # Skip if not a file
                    if not os.path.isfile(file_path):
                        continue
                        
                    # Get file modification time
                    mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
                    
                    # Delete if older than cutoff
                    if mod_time < cutoff_time:
                        try:
                            os.remove(file_path)
                            if file_path in self.tracked_downloads:
                                self.tracked_downloads.remove(file_path)
                            deleted_count += 1
                        except Exception as e:
                            logger.error(f"Failed to delete old file {file_path}: {str(e)}")
                
                logger.info(f"Cleaned up {deleted_count} old downloaded media files")
        except Exception as e:
            logger.error(f"Error cleaning up old downloads: {str(e)}")
            
    async def _schedule_media_cleanup(self):
        """Schedule periodic media cleanup."""
        try:
            while True:
                # Run cleanup every 6 hours
                await asyncio.sleep(6 * 60 * 60)
                await self._cleanup_old_downloads()
                
                # Check disk space after cleanup
                if not self._check_disk_space():
                    logger.warning("Disk space still above threshold after regular cleanup, forcing more aggressive cleanup")
                    await self._cleanup_old_downloads(force=True)
        except asyncio.CancelledError:
            logger.debug("Media cleanup task cancelled")
        except Exception as e:
            logger.error(f"Error in media cleanup task: {str(e)}")
            
    async def close(self):
        """Close Telegram clients."""
        if self._main_client:
            await self._main_client.disconnect()
            logger.info("Telegram client disconnected")
        
        for client in self.clients.values():
            await client.disconnect()
