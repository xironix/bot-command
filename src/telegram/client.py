"""
Telegram client module for silently monitoring stealer bots.

This module handles the connection to Telegram's API and intercepts messages
without modifying the original bot's behavior.
"""

import asyncio
import logging
import os
import shutil
import binascii # Needed for base64 errors during download
from datetime import datetime, timedelta
from typing import Dict, Callable, Any, Optional, Union, Coroutine

from telethon import TelegramClient, events, errors
from telethon.tl import types
from telethon.sessions import StringSession # Can use StringSession if needed, file default is fine

from config.settings import config
from src.storage.mongo_client import MongoDBManager

logger = logging.getLogger(__name__)

class TelegramMonitor:
    """Monitors Telegram bots by polling updates for each bot token."""
    
    def __init__(self, message_handler: Callable[[Dict[str, Any]], Coroutine]):
        """
        Initialize Telegram monitor.
        
        Args:
            message_handler: Async callback function to handle intercepted messages
        """
        self.config = config.telegram
        self._message_handler = message_handler
        self.bot_clients: Dict[str, TelegramClient] = {} # token -> client
        self.polling_tasks: Dict[str, asyncio.Task] = {} # token -> task
        self.mongo = MongoDBManager()
        self._shutdown_event = asyncio.Event() # Event to signal shutdown
        
        # Media file management
        self.downloads_dir = os.path.abspath("downloads")
        self.tracked_downloads = set()  # Set of downloaded files being tracked
        self.media_retention_days = int(os.getenv("MEDIA_RETENTION_DAYS", "30"))
        self.max_disk_usage_gb = float(os.getenv("MAX_DISK_USAGE_GB", "10"))
        
        # Create downloads directory if it doesn't exist
        os.makedirs(self.downloads_dir, exist_ok=True)
        
    async def initialize(self):
        """Initialize Telegram clients and connections for active bots."""
        logger.info("Initializing Telegram Monitor...")
        self._shutdown_event.clear() # Ensure shutdown event is not set
        
        try:
            # Get active bot tokens from MongoDB
            active_tokens = await self.mongo.get_active_bot_tokens()
            if not active_tokens:
                logger.warning("No active bot tokens found in database. Monitor will not start any clients.")
                return
            
            logger.info(f"Found {len(active_tokens)} active bot tokens. Initializing clients...")
            
            init_tasks = []
            for token in active_tokens:
                # Create a task for each bot initialization
                init_tasks.append(asyncio.create_task(self._initialize_bot_client(token)))
            
            # Wait for all initialization tasks to complete
            results = await asyncio.gather(*init_tasks, return_exceptions=True)
            
            successful_inits = 0
            for i, result in enumerate(results):
                token = active_tokens[i]
                if isinstance(result, Exception):
                    logger.error(f"Failed to initialize client for token {token[:10]}...: {result}")
                elif result: # _initialize_bot_client returns True on success
                    successful_inits += 1
                # else: _initialize_bot_client returned False (e.g., connection failed)
            
            if successful_inits == 0 and active_tokens:
                 logger.error("Failed to initialize any bot clients. Telegram monitoring will not function.")
                 # Decide if we should raise an error here or just log
                 # raise RuntimeError("Failed to initialize any Telegram bot clients.")
            else:
                 logger.info(f"Successfully initialized {successful_inits}/{len(active_tokens)} bot clients.")
            
            # Schedule cleanup tasks (only if any clients initialized)
            if successful_inits > 0:
                asyncio.create_task(self._schedule_media_cleanup())
                # Clean up any leftover files from previous runs
                await self._cleanup_old_downloads()
            
            logger.info("Telegram monitor initialization complete.")
            
        except Exception as e:
            logger.error(f"Critical error during Telegram client initialization process: {str(e)}", exc_info=True)
            await self.close() # Attempt graceful shutdown on critical init failure
            raise # Re-raise the exception
        
    async def _initialize_bot_client(self, token: str) -> bool:
        """Initializes and starts polling for a single bot token."""
        session_name = f"bot_{token[:10]}"
        logger.debug(f"Initializing client for token {token[:10]}... (Session: {session_name})")
        client: Optional[TelegramClient] = None # Explicitly type hint
        try:
            client = TelegramClient(
                session_name,
                self.config.api_id,
                self.config.api_hash,
            )
            
            await client.connect()
            
            if not await client.is_user_authorized():
                 logger.info(f"Attempting to sign in with bot token {token[:10]}...")
                 try:
                      await client.sign_in(bot_token=token)
                      logger.info(f"Successfully signed in with bot token {token[:10]}.")
                 except errors.AuthKeyError:
                      logger.error(f"Authentication failed for token {token[:10]}...: Invalid token or token revoked.")
                      await client.disconnect()
                      return False
                 except errors.ApiIdInvalidError:
                      logger.error(f"Authentication failed for token {token[:10]}...: Invalid api_id/api_hash.")
                      await client.disconnect()
                      # This is a fatal config error, maybe raise?
                      return False
                 except Exception as auth_err:
                      logger.error(f"Unexpected error signing in with token {token[:10]}...: {auth_err}", exc_info=True)
                      await client.disconnect()
                      return False
            else:
                 logger.info(f"Client for token {token[:10]}... is already authorized.")
                 me = await client.get_me() # me can be User or None

                 # Explicitly check if me is None first
                 if me is None:
                      logger.warning(f"Client for token {token[:10]}... get_me() returned None after authorization.")
                 elif isinstance(me, types.User):
                      # Now we know me is a User, access attributes safely
                      if not me.bot:
                           logger.warning(f"Client for token {token[:10]}... authorized but not as a bot? Type: {type(me)}")
                      elif me.id != int(token.split(':')[0]):
                           logger.warning(f"Client for token {token[:10]}... authorized as wrong bot ID ({me.id})? Session conflict?")
                      else:
                           logger.debug(f"Verified authorization for bot {me.username} ({me.id})")
                 else:
                      # Handle unexpected types returned by get_me()
                      logger.warning(f"Client for token {token[:10]}... get_me() returned unexpected type: {type(me)}")

            self.bot_clients[token] = client
            task = asyncio.create_task(self._poll_updates(token, client))
            self.polling_tasks[token] = task
            logger.info(f"Started polling updates for bot token {token[:10]}...")
            return True

        except errors.FloodWaitError as e:
            logger.error(f"Flood wait error initializing client for token {token[:10]}...: Waiting {e.seconds}s")
            await asyncio.sleep(e.seconds + 5)
            # Check client is not None before accessing methods
            if client and client.is_connected(): await client.disconnect()
            return False
        except ConnectionError as e:
            logger.error(f"Connection error initializing client for token {token[:10]}...: {e}")
            if client and client.is_connected(): await client.disconnect()
            return False
        except Exception as e:
            logger.error(f"Unexpected error initializing client for token {token[:10]}...: {str(e)}", exc_info=True)
            if client and client.is_connected():
                await client.disconnect()
            return False
        
    async def _poll_updates(self, token: str, client: TelegramClient):
        """Continuously poll for updates for a specific bot client."""
        bot_info: Optional[Dict] = None # Type hint
        retries = 0
        max_retries = 5
        retry_delay = 5 # seconds

        while not self._shutdown_event.is_set():
            try:
                if not client.is_connected():
                    logger.warning(f"Client for token {token[:10]}... disconnected. Attempting reconnect...")
                    await client.connect()
                    if not await client.is_user_authorized():
                         logger.warning(f"Client for {token[:10]}... requires re-authentication after reconnect.")
                         # Attempt re-auth or handle appropriately, maybe stop polling?
                         await client.sign_in(bot_token=token) # May raise errors
                    logger.info(f"Client for token {token[:10]}... reconnected.")

                # Get bot info once
                if bot_info is None:
                    me = await client.get_me()
                    # Ensure me is a User and is a bot before setting bot_info
                    if isinstance(me, types.User) and me.bot:
                        bot_info = {"id": me.id, "username": me.username}
                        logger.debug(f"Polling as bot: {bot_info['username']} ({bot_info['id']})")
                    else:
                        logger.error(f"Failed to get bot identity (or not a bot) for token {token[:10]}... Stopping poll. Got: {type(me)}")
                        break # Stop polling if we can't identify the bot

                # Use iter_messages with entity='me' to poll for incoming messages to the bot itself
                logger.debug(f"Polling for messages for bot {bot_info['username']}...")
                async for message in client.iter_messages('me', limit=10, wait_time=60):
                    if self._shutdown_event.is_set(): break

                    logger.info(f"Received message (ID: {message.id}) for bot {bot_info['username']}")
                    asyncio.create_task(self._process_incoming_message(token, client, message, bot_info))

                retries = 0

            except errors.AuthKeyError:
                logger.error(f"Authentication key error for bot token {token[:10]}... Token likely revoked. Stopping poll.")
                await self.mongo.update_bot_status(token=token, status="inactive")
                break
            except errors.UserDeactivatedError:
                 logger.error(f"Bot account for token {token[:10]}... is deactivated. Stopping poll.")
                 await self.mongo.update_bot_status(token=token, status="inactive")
                 break
            except errors.RPCError as e:
                 logger.error(f"Telegram RPC Error for bot {bot_info['username'] if bot_info else token[:10]}: {e}")
                 if retries < max_retries:
                      retries += 1
                      logger.warning(f"Retrying poll for {bot_info['username'] if bot_info else token[:10]} in {retry_delay}s (Attempt {retries}/{max_retries})")
                      await asyncio.sleep(retry_delay)
                 else:
                      logger.error(f"Max retries reached for bot {bot_info['username'] if bot_info else token[:10]}. Stopping poll.")
                      await self.mongo.update_bot_status(token=token, status="error")
                      break
            except asyncio.CancelledError:
                 logger.info(f"Polling task for bot {bot_info['username'] if bot_info else token[:10]} cancelled.")
                 break
            except Exception as e:
                logger.error(f"Unexpected error in polling loop for bot {bot_info['username'] if bot_info else token[:10]}: {str(e)}", exc_info=True)
                if retries < max_retries:
                      retries += 1
                      logger.warning(f"Retrying poll for {bot_info['username'] if bot_info else token[:10]} in {retry_delay * 2}s (Attempt {retries}/{max_retries})")
                      await asyncio.sleep(retry_delay * 2)
                else:
                      logger.error(f"Max retries reached for bot {bot_info['username'] if bot_info else token[:10]} after unexpected error. Stopping poll.")
                      await self.mongo.update_bot_status(token=token, status="error")
                      break

        logger.info(f"Polling stopped for bot token {token[:10]}...")
        # Ensure client is removed if polling stops
        if token in self.bot_clients:
            del self.bot_clients[token]
        if token in self.polling_tasks:
             del self.polling_tasks[token]
        if client.is_connected():
            await client.disconnect()
        
    async def _process_incoming_message(self, token: str, client: TelegramClient, message: types.Message, bot_info: Dict):
        """Process a message received by a specific bot."""
        try:
            sender_info = {}
            sender_entity = None
            # Use getattr for safer access to from_id (often more reliable than sender_id)
            from_id = getattr(message, 'from_id', None)

            # Check if from_id exists before trying to get the entity
            if from_id:
                try:
                     # Use get_entity which handles various peer types
                     # Note: get_entity works with Peer objects, from_id should be a Peer type
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
                     # Check for Channel (supergroups/channels) which have usernames
                     elif isinstance(sender_entity, types.Channel):
                           sender_info = {
                                "id": sender_entity.id,
                                "title": sender_entity.title,
                                "username": sender_entity.username, # Channels have usernames
                                "type": type(sender_entity).__name__
                           }
                     # Check for Chat (small groups) which do *not* have usernames
                     elif isinstance(sender_entity, types.Chat):
                          sender_info = {
                               "id": sender_entity.id,
                               "title": sender_entity.title,
                               # No username for basic Chat type
                               "type": type(sender_entity).__name__
                          }
                except ValueError:
                     # This might happen if from_id is None or refers to an inaccessible peer
                     logger.warning(f"Could not get entity for from_id: {from_id}")
                except Exception as e:
                     logger.error(f"Error getting sender entity for from_id {from_id}: {e}")
            # If from_id was None or couldn't be resolved, sender_info remains {}

            msg_date = getattr(message, 'date', None)

            # Extract relevant data from the message, using getattr for safety
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

            # If media is present, download it using the correct client
            if message.media:
                try:
                    media_path = await self._download_media(client, message) # Pass the client instance
                    if media_path:
                        data["media_path"] = media_path
                    else:
                         # Update data if download failed but media exists
                         data["media_download_failed"] = True
                except Exception as e:
                    logger.error(f"Failed processing media for message {message.id}: {str(e)}", exc_info=True)
                    data["media_download_failed"] = True
                    data["media_download_error"] = str(e)

            # Pass to the coordinator's handler
            await self._message_handler(data)

        except Exception as e:
            logger.error(f"Failed to process incoming message {getattr(message, 'id', 'UNKNOWN')} for bot {bot_info['username']}: {str(e)}", exc_info=True)
        
    async def _download_media(self, client: TelegramClient, message: types.Message) -> Optional[str]:
        """
        Download media from a message using the specific bot's client.
        
        Args:
            client: The TelegramClient instance associated with the bot.
            message: Telegram message with media.
            
        Returns:
            Path to the downloaded media or None if download failed.
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
            
            # Generate a unique filename based on bot_id and message_id
            # Await get_me() before accessing its attributes
            me = await client.get_me()
            if not me or not hasattr(me, 'id'): # Ensure me and me.id exist
                 logger.error(f"Could not determine client bot ID for download. Client: {client}")
                 return None
            bot_id = me.id

            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
            filename_base = f"bot{bot_id}_msg{message.id}_{timestamp}"
            filepath_base = os.path.join(self.downloads_dir, filename_base)
            
            # Download the media
            path = await client.download_media(message, filepath_base)

            # Ensure path is a string and exists before returning
            if path and isinstance(path, str) and os.path.exists(path):
                self.tracked_downloads.add(path)
                logger.debug(f"Downloaded media to {path} using bot {bot_id}")
                return path
            elif path:
                 # Log if path was returned but wasn't a valid string or didn't exist
                 logger.warning(f"Download for msg {message.id} by bot {bot_id} returned path '{path}' (type: {type(path)}), but it's invalid or non-existent.")
                 return None
            else:
                 logger.warning(f"Download initiated for message {message.id} by bot {bot_id} but path was None.")
                 return None
        except errors.FileReferenceExpiredError:
             logger.warning(f"File reference expired for media in message {message.id}. Cannot download.")
             # Maybe try to refetch the message? For now, just return None.
             return None
        except (binascii.Error, TypeError) as b64_err:
             # Catch potential errors during download related to base64 decoding (rare)
             logger.error(f"Base64 related error downloading media for message {message.id}: {b64_err}")
             return None
        except Exception as e:
            logger.error(f"Failed to download media for message {message.id}: {str(e)}", exc_info=True)
            return None
        
    def _check_disk_space(self) -> bool:
        """Check if disk usage is within limits."""
        try:
            total, used, free = shutil.disk_usage(self.downloads_dir)
            used_gb = used / (1024**3)
            if used_gb > self.max_disk_usage_gb:
                logger.warning(f"Disk usage ({used_gb:.2f} GB) exceeds limit ({self.max_disk_usage_gb} GB)")
                return False
            return True
        except Exception as e:
            logger.error(f"Error checking disk space: {str(e)}")
            return True # Default to true if check fails to avoid blocking downloads
        
    async def _cleanup_old_downloads(self, force: bool = False):
        """Remove old downloaded media files."""
        logger.info(f"Running media cleanup. Retention: {self.media_retention_days} days. Force: {force}")
        now = datetime.utcnow()
        cutoff = now - timedelta(days=self.media_retention_days)
        cleaned_count = 0
        cleaned_size = 0

        # Also clean up self.tracked_downloads list for files that no longer exist
        missing_files = set()

        # Use a copy of the set for iteration as we might modify it
        current_tracked = list(self.tracked_downloads)

        for file_path in current_tracked:
             try:
                  if not os.path.exists(file_path):
                       missing_files.add(file_path)
                       continue

                  # Get file modification time (UTC)
                  mod_time_ts = os.path.getmtime(file_path)
                  mod_time = datetime.utcfromtimestamp(mod_time_ts)

                  if mod_time < cutoff or force:
                       file_size = os.path.getsize(file_path)
                       os.remove(file_path)
                       logger.debug(f"Deleted old media file: {file_path} (Modified: {mod_time})")
                       self.tracked_downloads.discard(file_path) # Remove from tracking
                       cleaned_count += 1
                       cleaned_size += file_size

             except FileNotFoundError:
                  missing_files.add(file_path) # Already gone
             except Exception as e:
                  logger.error(f"Error deleting media file {file_path}: {str(e)}")

        # Clean up tracked set
        if missing_files:
             logger.debug(f"Removing {len(missing_files)} non-existent files from tracked downloads.")
             self.tracked_downloads.difference_update(missing_files)

        # Also scan directory for untracked old files (e.g., from crashes)
        logger.debug(f"Scanning {self.downloads_dir} for any untracked old files...")
        try:
             for filename in os.listdir(self.downloads_dir):
                  file_path = os.path.join(self.downloads_dir, filename)
                  if file_path in self.tracked_downloads: # Skip already checked tracked files
                       continue

                  try:
                       if os.path.isfile(file_path):
                            mod_time_ts = os.path.getmtime(file_path)
                            mod_time = datetime.utcfromtimestamp(mod_time_ts)
                            if mod_time < cutoff:
                                 file_size = os.path.getsize(file_path)
                                 os.remove(file_path)
                                 logger.debug(f"Deleted untracked old media file: {file_path} (Modified: {mod_time})")
                                 cleaned_count += 1
                                 cleaned_size += file_size
                  except FileNotFoundError:
                       continue # File might have been deleted between listdir and stat
                  except Exception as e:
                       logger.error(f"Error processing untracked file {file_path} during cleanup: {e}")

        except Exception as e:
             logger.error(f"Error scanning downloads directory during cleanup: {e}")

        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} old media files (Total size: {cleaned_size / (1024*1024):.2f} MB).")
        else:
            logger.info("No old media files found needing cleanup.")
        
    async def _schedule_media_cleanup(self):
        """Periodically run the media cleanup task."""
        while not self._shutdown_event.is_set():
            try:
                # Wait for 24 hours before next cleanup
                await asyncio.wait_for(self._shutdown_event.wait(), timeout=24 * 3600)
                # If wait finishes without timeout, shutdown was triggered
                break
            except asyncio.TimeoutError:
                # Timeout occurred, run cleanup
                await self._cleanup_old_downloads()
            except asyncio.CancelledError:
                 logger.info("Media cleanup scheduler cancelled.")
                 break
            except Exception as e:
                 logger.error(f"Error in media cleanup scheduler: {e}")
                 # Wait a shorter interval before retrying after an error
                 await asyncio.sleep(3600) # Wait 1 hour before retry after error

        logger.info("Media cleanup scheduler stopped.")
        
    async def close(self):
        """Shut down all Telegram clients and tasks."""
        logger.info(f"Shutting down Telegram Monitor. Closing {len(self.polling_tasks)} polling tasks...")
        self._shutdown_event.set() # Signal all loops to stop

        # Cancel all polling tasks
        tasks_to_cancel = list(self.polling_tasks.values())
        for task in tasks_to_cancel:
            if not task.done():
                task.cancel()

        # Wait for tasks to finish cancellation
        if tasks_to_cancel:
             await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
             logger.debug("Polling tasks cancellation complete.")

        # Disconnect all clients
        clients_to_disconnect = list(self.bot_clients.values())
        logger.info(f"Disconnecting {len(clients_to_disconnect)} Telegram clients...")
        disconnect_tasks = []
        for client in clients_to_disconnect:
            if client.is_connected():
                disconnect_tasks.append(asyncio.create_task(client.disconnect()))

        if disconnect_tasks:
            await asyncio.gather(*disconnect_tasks, return_exceptions=True)
            logger.debug("Client disconnection complete.")

        self.bot_clients.clear()
        self.polling_tasks.clear()
        logger.info("Telegram Monitor shut down.")
