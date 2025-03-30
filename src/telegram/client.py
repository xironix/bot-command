"""
Telegram client module for silently monitoring stealer bots.

This module handles the connection to Telegram's API and intercepts messages
without modifying the original bot's behavior.
"""

import asyncio
import logging
import os
import shutil
import binascii
from datetime import datetime, timedelta
from typing import Dict, List, Callable, Any, Optional, Union, Coroutine

from telethon import TelegramClient, events, errors, types, utils
from telethon.sessions import StringSession
from pymongo.errors import PyMongoError

from config.settings import config
from src.storage.mongo_client import MongoDBManager
from src.utils.base_client import BaseAsyncClient
from src.utils.error_handler import RetryHandler, ErrorLogger

class TelegramMonitor(BaseAsyncClient):
    """Monitors Telegram bots by polling updates for each bot token."""
    
    def __init__(self, message_handler: Callable[..., Coroutine[Any, Any, None]]):
        """
        Initialize Telegram monitor.
        
        Args:
            message_handler: Async callback function to handle intercepted messages
        """
        super().__init__("telegram_monitor")
        self.config = config.telegram
        self._message_handler = message_handler
        self.bot_clients: Dict[str, TelegramClient] = {}
        self.polling_tasks: Dict[str, asyncio.Task] = {}
        self.mongo = MongoDBManager()
        
        # Media file management
        self.downloads_dir = os.path.abspath("downloads")
        self.tracked_downloads = set()
        
        # Session file management
        self.sessions_dir = os.path.abspath("sessions")
        
        # Create directories
        os.makedirs(self.downloads_dir, exist_ok=True)
        os.makedirs(self.sessions_dir, exist_ok=True)
        
    async def _initialize_client(self) -> bool:
        """
        Initialize Telegram clients for active bots.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        active_bots: List[Dict[str, str]] = []
        try:
            # Get active bots 
            active_bots = await self.mongo.get_active_bots()
            if not active_bots:
                self.logger.warning("No active bot tokens found. Monitor will not start any clients.")
                return False
            
            self.logger.info(f"Found {len(active_bots)} active bots. Initializing clients...")
            
            init_tasks = []
            tokens_for_tasks = []
            for bot_data in active_bots:
                token = bot_data.get("token")
                if isinstance(token, str) and ':' in token:
                    init_tasks.append(asyncio.create_task(self._initialize_bot_client(token)))
                    tokens_for_tasks.append(token)
                else:
                    self.logger.warning(f"Skipping bot data with invalid/missing token: {bot_data}")
            
            if not init_tasks:
                self.logger.warning("No valid bot tokens found to initialize.")
                return False

            # Wait for all initialization tasks
            results = await asyncio.gather(*init_tasks, return_exceptions=True)
            
            successful_inits = 0
            for i, result in enumerate(results):
                token = tokens_for_tasks[i] 
                
                if isinstance(result, Exception):
                    self.logger.error(f"Failed to initialize client for token {token[:10]}...: {result}", 
                                     exc_info=isinstance(result, PyMongoError))
                elif result:
                    successful_inits += 1
            
            if successful_inits == 0 and active_bots:
                self.logger.error("Failed to initialize any bot clients. Monitoring will not function.")
                return False
            else:
                self.logger.info(f"Successfully initialized {successful_inits}/{len(init_tasks)} bot clients.")
            
            # Schedule cleanup if any clients initialized
            if successful_inits > 0:
                asyncio.create_task(self._schedule_media_cleanup())
                await self._cleanup_old_downloads()
            
            return True
            
        except PyMongoError as e:
            self.logger.error(f"Database error during initialization: {e}", exc_info=True)
            return False
        except Exception as e:
            self.logger.error(f"Critical error during initialization: {e}", exc_info=True)
            return False
    
    async def _shutdown_client(self) -> None:
        """Shutdown all Telegram clients and tasks."""
        # Cancel all polling tasks
        tasks_to_cancel = list(self.polling_tasks.values())
        for task in tasks_to_cancel:
            if not task.done():
                task.cancel()

        # Wait for tasks to finish cancellation
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
            self.logger.debug("Polling tasks cancellation complete.")

        # Disconnect all clients
        clients_to_disconnect = list(self.bot_clients.values())
        self.logger.info(f"Disconnecting {len(clients_to_disconnect)} Telegram clients...")
        disconnect_tasks = []
        for client in clients_to_disconnect:
            if client and client.is_connected(): 
                try:
                    disconnect_result = client.disconnect()
                    if hasattr(disconnect_result, 'add_done_callback'):
                        disconnect_tasks.append(disconnect_result)
                    else:
                        disconnect_tasks.append(asyncio.create_task(disconnect_result))
                except Exception as e:
                    self.logger.warning(f"Error disconnecting client: {e}")
            elif client:
                self.logger.debug(f"Client {client.session.filename} already disconnected.")

        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
            self.logger.debug("Client disconnection complete.")

        self.bot_clients.clear()
        self.polling_tasks.clear()
        self.logger.info("Telegram Monitor shut down.")
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get Telegram monitor status.
        
        Returns:
            Dictionary with status information
        """
        return {
            "name": self.name,
            "initialized": self.initialized,
            "active_clients": len(self.bot_clients),
            "polling_tasks": len(self.polling_tasks),
            "api_configured": bool(self.config.api_id and self.config.api_hash),
            "webhook_configured": bool(hasattr(self.config, 'webhook_base_url') and self.config.webhook_base_url)
        }
        
    @RetryHandler.async_retry(max_retries=2, retry_delay=5.0)
    async def _initialize_bot_client(self, token: str) -> bool:
        """Initializes and starts polling for a single bot token."""
        if not self.config.api_id or not self.config.api_hash:
            self.logger.error("Telegram API ID or API Hash is missing. Cannot initialize client.")
            return False

        session_name_base = f"bot_{token[:10]}"
        session_path = os.path.join(self.sessions_dir, session_name_base)
        self.logger.debug(f"Initializing client for token {token[:10]}... (Session: {session_path})")
        
        client: Optional[TelegramClient] = None
        try:
            client = TelegramClient(session_path, self.config.api_id, self.config.api_hash)
            await client.connect()
            
            if not await client.is_user_authorized():
                self.logger.info(f"Attempting to sign in with bot token {token[:10]}...")
                try:
                    await client.sign_in(bot_token=token)
                    self.logger.info(f"Successfully signed in with bot token {token[:10]}.")
                except errors.AuthKeyError:
                    self.logger.error(f"Authentication failed: Invalid token or token revoked.")
                    if client: await client.disconnect() 
                    return False
                except errors.ApiIdInvalidError:
                    self.logger.error(f"Authentication failed: Invalid api_id/api_hash.")
                    if client: await client.disconnect() 
                    return False
                except Exception as auth_err:
                    self.logger.error(f"Unexpected error signing in: {auth_err}", exc_info=True)
                    if client: await client.disconnect() 
                    return False
            else:
                self.logger.info(f"Client for token {token[:10]}... is already authorized.")
                me = await client.get_me()

                if me is None:
                    self.logger.warning(f"get_me() returned None after authorization.")
                elif isinstance(me, types.User):
                    if not me.bot:
                        self.logger.warning(f"Authorized but not as a bot? Type: {type(me)}")
                    elif me.id != int(token.split(':')[0]):
                        self.logger.warning(f"Authorized as wrong bot ID ({me.id})? Session conflict?")
                    else:
                        self.logger.debug(f"Verified authorization for bot {me.username} ({me.id})")
                else:
                    self.logger.warning(f"get_me() returned unexpected type: {type(me)}")

            self.bot_clients[token] = client

            # Start polling if webhooks not configured
            webhook_configured = hasattr(self.config, 'webhook_base_url') and self.config.webhook_base_url
            
            if not webhook_configured:
                self.logger.info(f"Webhooks not configured, starting polling for {token[:10]}...")
                task = asyncio.create_task(self._poll_updates(token, client))
                self.polling_tasks[token] = task
            else:
                self.logger.info(f"Webhooks configured, skipping polling for {token[:10]}...")
            
            return True

        except errors.FloodWaitError as e:
            self.logger.error(f"Flood wait error: Waiting {e.seconds}s")
            await asyncio.sleep(e.seconds + 5)
            if client and client.is_connected():
                await client.disconnect()
            return False
        except ConnectionError as e:
            self.logger.error(f"Connection error: {e}")
            if client and client.is_connected():
                await client.disconnect()
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}", exc_info=True)
            if client and client.is_connected():
                await client.disconnect()
            return False
        
    async def _poll_updates(self, token: str, client: TelegramClient):
        """Continuously poll for updates for a specific bot client."""
        bot_info: Optional[Dict] = None
        retries = 0
        max_retries = 5
        retry_delay = 5

        while not self.is_shutdown_requested():
            try:
                if not client.is_connected():
                    self.logger.warning(f"Client disconnected. Attempting reconnect...")
                    await client.connect()
                    if not await client.is_user_authorized():
                        self.logger.warning(f"Client requires re-authentication after reconnect.")
                        await client.sign_in(bot_token=token)
                    self.logger.info(f"Client reconnected.")

                # Get bot info once
                if bot_info is None:
                    me = await client.get_me()
                    if isinstance(me, types.User) and me.bot:
                        bot_info = {"id": me.id, "username": me.username}
                        self.logger.debug(f"Polling as bot: {bot_info['username']} ({bot_info['id']})")
                    else:
                        self.logger.error(f"Failed to get bot identity. Stopping poll.")
                        break

                # Poll for messages
                self.logger.debug(f"Polling for messages for bot {bot_info['username']}...")
                async for message in client.iter_messages('me', limit=10, wait_time=60):
                    if self.is_shutdown_requested(): break

                    self.logger.info(f"Received message (ID: {message.id}) for bot {bot_info['username']}")
                    asyncio.create_task(self._process_incoming_message(token, client, message, bot_info))

                retries = 0

            except errors.AuthKeyError:
                self.logger.error(f"Authentication key error. Token likely revoked. Stopping poll.")
                await self.mongo.update_bot_status(token=token, status="inactive")
                break
            except errors.UserDeactivatedError:
                self.logger.error(f"Bot account is deactivated. Stopping poll.")
                await self.mongo.update_bot_status(token=token, status="inactive")
                break
            except errors.RPCError as e:
                self.logger.error(f"Telegram RPC Error: {e}")
                if retries < max_retries:
                    retries += 1
                    self.logger.warning(f"Retrying poll in {retry_delay}s (Attempt {retries}/{max_retries})")
                    await asyncio.sleep(retry_delay)
                else:
                    self.logger.error(f"Max retries reached. Stopping poll.")
                    await self.mongo.update_bot_status(token=token, status="error")
                    break
            except asyncio.CancelledError:
                self.logger.info(f"Polling task cancelled.")
                break
            except Exception as e:
                self.logger.error(f"Unexpected error in polling loop: {str(e)}", exc_info=True)
                if retries < max_retries:
                    retries += 1
                    self.logger.warning(f"Retrying poll in {retry_delay * 2}s (Attempt {retries}/{max_retries})")
                    await asyncio.sleep(retry_delay * 2)
                else:
                    self.logger.error(f"Max retries reached after unexpected error. Stopping poll.")
                    await self.mongo.update_bot_status(token=token, status="error")
                    break

        self.logger.info(f"Polling stopped for bot token {token[:10]}...")
        # Clean up resources
        if token in self.bot_clients:
            del self.bot_clients[token]
        if token in self.polling_tasks:
            del self.polling_tasks[token]
        if client.is_connected():
            await client.disconnect()
        
    @ErrorLogger.async_safe_operation(default_value=None)
    async def _process_incoming_message(self, token: str, client: TelegramClient, message: types.Message, bot_info: Dict):
        """Process a single incoming message."""
        # Basic message info for logging
        chat_id = utils.get_peer_id(message.peer_id) 
        msg_info = f"Message ID {message.id} from chat {chat_id}"
        self.logger.debug(f"Processing {msg_info} for bot {bot_info.get('username', 'UNKNOWN')}")

        sender_info = {}
        from_id = getattr(message, 'from_id', None)

        if from_id:
            try:
                sender_entity = await client.get_entity(from_id)
                if isinstance(sender_entity, types.User):
                    sender_info = {
                        "id": sender_entity.id,
                        "username": sender_entity.username,
                        "first_name": sender_entity.first_name,
                        "last_name": sender_entity.last_name,
                        "is_bot": sender_entity.bot,
                        "is_premium": sender_entity.premium
                    }
                elif isinstance(sender_entity, types.Channel):
                    sender_info = {
                        "id": sender_entity.id,
                        "title": sender_entity.title,
                        "username": sender_entity.username,
                        "type": type(sender_entity).__name__
                    }
                elif isinstance(sender_entity, types.Chat):
                    sender_info = {
                        "id": sender_entity.id,
                        "title": sender_entity.title,
                        "type": type(sender_entity).__name__
                    }
            except ValueError:
                self.logger.warning(f"Could not get entity for from_id: {from_id}")
            except Exception as e:
                self.logger.error(f"Error getting sender entity: {e}")

        msg_date = getattr(message, 'date', None)

        # Extract data from message
        data = {
            "bot_id": bot_info["id"],
            "bot_username": bot_info["username"],
            "message_id": message.id,
            "chat_id": getattr(message, 'chat_id', None),
            "sender": sender_info,
            "timestamp": msg_date.replace(tzinfo=None) if msg_date else None,
            "text": getattr(message, 'text', ""),
            "has_media": message.media is not None,
            "media_type": type(message.media).__name__ if message.media else None,
            "raw_message": message.to_dict()
        }

        # Handle media if present
        if message.media:
            try:
                media_path = await self._download_media(client, message)
                if media_path:
                    data["media_path"] = media_path
                else:
                    data["media_download_failed"] = True
            except Exception as e:
                self.logger.error(f"Failed processing media: {str(e)}", exc_info=True)
                data["media_download_failed"] = True
                data["media_download_error"] = str(e)

        # Pass to handler
        await self._message_handler(data)
        
    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def _download_media(self, client: TelegramClient, message: types.Message) -> Optional[str]:
        """
        Download media from a message.
        
        Args:
            client: The TelegramClient instance
            message: Telegram message with media
            
        Returns:
            Path to downloaded media or None if failed
        """
        # Check disk space
        if not self._check_disk_space():
            self.logger.warning("Disk space threshold exceeded, cleaning old downloads")
            await self._cleanup_old_downloads(force=True)
            
            if not self._check_disk_space():
                self.logger.error("Insufficient disk space even after cleanup")
                return None
        
        # Get bot ID
        me = await client.get_me()
        if not isinstance(me, types.User):
            self.logger.error(f"Could not determine client bot ID (type: {type(me)})")
            return None
        bot_id = me.id

        # Generate unique filename
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
        filename_base = f"bot{bot_id}_msg{message.id}_{timestamp}"
        filepath_base = os.path.join(self.downloads_dir, filename_base)
        
        # Download media
        path = await client.download_media(message, filepath_base)

        # Validate result
        if path and isinstance(path, str) and os.path.exists(path):
            self.tracked_downloads.add(path)
            self.logger.debug(f"Downloaded media to {path}")
            return path
        elif path:
            self.logger.warning(f"Download returned invalid path: '{path}'")
            return None
        else:
            self.logger.warning(f"Download returned None")
            return None
        
    def _check_disk_space(self) -> bool:
        """Check if disk usage is within limits."""
        try:
            total, used, free = shutil.disk_usage(self.downloads_dir)
            used_gb = used / (1024**3)
            if used_gb > self.config.max_disk_usage_gb:
                self.logger.warning(f"Disk usage ({used_gb:.2f} GB) exceeds limit ({self.config.max_disk_usage_gb} GB)")
                return False
            return True
        except Exception as e:
            self.logger.error(f"Error checking disk space: {str(e)}")
            return True # Default to true if check fails
        
    async def _cleanup_old_downloads(self, force: bool = False):
        """Remove old downloaded media files."""
        self.logger.info(f"Running media cleanup. Retention: {self.config.media_retention_days} days. Force: {force}")
        now = datetime.utcnow()
        cutoff = now - timedelta(days=self.config.media_retention_days)
        cleaned_count = 0
        cleaned_size = 0

        # Clean tracked downloads
        missing_files = set()
        current_tracked = list(self.tracked_downloads)

        for file_path in current_tracked:
            try:
                if not os.path.exists(file_path):
                    missing_files.add(file_path)
                    continue

                mod_time_ts = os.path.getmtime(file_path)
                mod_time = datetime.utcfromtimestamp(mod_time_ts)

                if mod_time < cutoff or force:
                    file_size = os.path.getsize(file_path)
                    os.remove(file_path)
                    self.logger.debug(f"Deleted old media file: {file_path}")
                    self.tracked_downloads.discard(file_path)
                    cleaned_count += 1
                    cleaned_size += file_size
            except FileNotFoundError:
                missing_files.add(file_path)
            except Exception as e:
                self.logger.error(f"Error deleting file {file_path}: {str(e)}")

        # Clean up tracked set
        if missing_files:
            self.logger.debug(f"Removing {len(missing_files)} non-existent files from tracking.")
            self.tracked_downloads.difference_update(missing_files)

        # Scan for untracked files
        try:
            for filename in os.listdir(self.downloads_dir):
                file_path = os.path.join(self.downloads_dir, filename)
                if file_path in self.tracked_downloads:
                    continue

                try:
                    if os.path.isfile(file_path):
                        mod_time_ts = os.path.getmtime(file_path)
                        mod_time = datetime.utcfromtimestamp(mod_time_ts)
                        if mod_time < cutoff:
                            file_size = os.path.getsize(file_path)
                            os.remove(file_path)
                            self.logger.debug(f"Deleted untracked file: {file_path}")
                            cleaned_count += 1
                            cleaned_size += file_size
                except FileNotFoundError:
                    continue
                except Exception as e:
                    self.logger.error(f"Error processing untracked file: {e}")
        except Exception as e:
            self.logger.error(f"Error scanning downloads directory: {e}")

        if cleaned_count > 0:
            self.logger.info(f"Cleaned {cleaned_count} files ({cleaned_size / (1024*1024):.2f} MB)")
        else:
            self.logger.info("No files needed cleanup")
        
    async def _schedule_media_cleanup(self):
        """Periodically run media cleanup."""
        while not self.is_shutdown_requested():
            try:
                # Wait for 24 hours or shutdown
                await self.wait_for_shutdown(timeout=24 * 3600)
                # If shutdown requested, exit loop
                if self.is_shutdown_requested():
                    break
                # Run cleanup
                await self._cleanup_old_downloads()
            except Exception as e:
                self.logger.error(f"Error in cleanup scheduler: {e}")
                await asyncio.sleep(3600) # Wait 1 hour after error

        self.logger.info("Media cleanup scheduler stopped")
