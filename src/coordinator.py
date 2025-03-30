"""
Main coordinator for the Bot-Command application.

This module orchestrates the various components of the application, including
Telegram monitoring, message processing, and data storage.
"""

import asyncio
import logging
import os
import json # Add json import for parsing potential error details
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

import aiohttp
from pymongo.errors import PyMongoError

from src.telegram.client import TelegramMonitor
from src.processing.worker_pool import WorkerPool
from src.processing.message_parser import MessageParser
from src.storage.mongo_client import MongoDBManager
from src.storage.elastic_client import ElasticsearchManager

logger = logging.getLogger(__name__)

class Coordinator:
    """Main coordinator for the Bot-Command application."""
    
    def __init__(self):
        """Initialize coordinator."""
        # Create component instances
        self.worker_pool = WorkerPool()
        self.message_parser = MessageParser()
        self.mongo_manager = MongoDBManager()
        self.elastic_manager = ElasticsearchManager()
        self.telegram_monitor = TelegramMonitor(self._handle_telegram_message)
        
        # State
        self.initialized = False
        self.last_stats_report = datetime.now()
        
        # Configuration 
        self.stats_report_interval = 3600  # Report stats every hour
        self.debug_mode = False
        self.stats_task: Optional[asyncio.Task] = None
        
    def enable_debug_mode(self, debug_dir: str = "debug_logs"):
        """
        Enable debug mode with detailed logging.
        
        Args:
            debug_dir: Directory for debug output
        """
        self.debug_mode = True
        
        # Enable debug on message parser
        self.message_parser.enable_debug(debug_dir)
        
        # Set worker pool logging to DEBUG
        worker_pool_logger = logging.getLogger("worker_pool")
        worker_pool_logger.setLevel(logging.DEBUG)
        
        # Set telegram monitor logging to DEBUG
        # telegram_logger = logging.getLogger("telegram") # Commented out as telegram monitor might change
        # telegram_logger.setLevel(logging.DEBUG)
        
        logger.info(f"Debug mode enabled, output will be saved to {debug_dir}")
        
    async def initialize(self):
        """Initialize all components."""
        if self.initialized:
            return
            
        logger.info("Initializing Bot-Command coordinator")
        
        try:
            # Initialize worker pool
            logger.debug("Initializing worker pool...")
            await self.worker_pool.start()
            logger.debug("Worker pool initialized.")
            
            # Initialize MongoDB manager
            logger.debug("Initializing MongoDB manager...")
            mongo_available = await self.mongo_manager.initialize()
            if not mongo_available:
                logger.error("MongoDB initialization failed, cannot continue")
                return
            logger.debug("MongoDB manager initialized successfully.")
            
            # Initialize Elasticsearch (if available)
            logger.debug("Initializing Elasticsearch manager...")
            elastic_available = await self.elastic_manager.initialize()
            if not elastic_available:
                logger.warning("Elasticsearch is not available, some features will be limited")
            logger.debug("Elasticsearch manager initialized (available: %s).", elastic_available)
                
            # Initialize Telegram monitor
            logger.debug("Initializing Telegram monitor...")
            telegram_available = await self.telegram_monitor.initialize()
            if not telegram_available:
                logger.warning("Telegram monitor initialization failed, monitoring capabilities will be limited")
            logger.debug("Telegram monitor initialized (available: %s).", telegram_available)
            
            self.initialized = True
            logger.info("Bot-Command coordinator initialized")
        except Exception as e:
            logger.error(f"Failed to initialize coordinator: {str(e)}", exc_info=True)
            # Attempt cleanup
            await self.shutdown()
        
    async def shutdown(self):
        """Shut down all components."""
        logger.info("Shutting down Bot-Command coordinator")
        
        shutdown_errors = []
        
        # Shut down worker pool
        try:
            await self.worker_pool.stop()
        except Exception as e:
            logger.error(f"Error stopping worker pool: {str(e)}")
            shutdown_errors.append(f"Worker pool: {str(e)}")
        
        # Close Telegram monitor
        try:
            await self.telegram_monitor.close()
        except Exception as e:
            logger.error(f"Error closing Telegram monitor: {str(e)}")
            shutdown_errors.append(f"Telegram monitor: {str(e)}")
        
        # Close Elasticsearch connection
        try:
            await self.elastic_manager.close()
        except Exception as e:
            logger.error(f"Error closing Elasticsearch manager: {str(e)}")
            shutdown_errors.append(f"Elasticsearch: {str(e)}")
        
        # Close MongoDB connection
        try:
            await self.mongo_manager.close()
        except Exception as e:
            logger.error(f"Error closing MongoDB manager: {str(e)}")
            shutdown_errors.append(f"MongoDB: {str(e)}")
        
        self.initialized = False
        
        if shutdown_errors:
            logger.warning(f"Bot-Command coordinator shut down with {len(shutdown_errors)} errors")
        else:
            logger.info("Bot-Command coordinator shut down cleanly")
        
    async def start_monitoring(self, bot_usernames: Optional[List[str]] = None):
        """
        Start monitoring specified bots (Likely unused with webhooks).
        
        Args:
            bot_usernames: List of bot usernames to monitor (optional)
        """
        if not self.initialized:
            await self.initialize()
            
        logger.info("Starting bot monitoring")
        
        # If no specific bots are provided, use the ones from config
        # This would be implemented in a production system
        
        # For each bot, set up monitoring
        if bot_usernames:
            for username in bot_usernames:
                # This would set up specific monitoring for each bot
                # In a real implementation, this might involve joining channels, etc.
                # await self.telegram_monitor.monitor_bot_channel(username)
                pass # Added pass to fix empty loop body
                
        # Start statistics reporting task (Moved to initialize or FastAPI startup)
        # asyncio.create_task(self._report_stats_periodically())
                
        # logger.info("Bot monitoring started")
        
    async def get_token_for_username(self, username: str) -> Optional[str]:
        """Fetches the bot token associated with a given username."""
        bot_info = await self.mongo_manager.get_bot_info(username=username)
        if bot_info and bot_info.get("status") == "active":
            return bot_info.get("token")
        return None

    # --- Webhook Handling --- 

    async def handle_webhook_update(self, token: str, update_data: Dict[str, Any]):
        """Handles an incoming webhook update from the FastAPI endpoint."""
        logger.debug(f"Coordinator received update for token {token[:4]}...: {list(update_data.keys())}")
        
        # Extract the main content (message, edited_message, etc.)
        # Telegram sends only one of these per update object.
        message_content = None
        update_type = "unknown"
        if "message" in update_data:
            message_content = update_data["message"]
            update_type = "message"
        elif "edited_message" in update_data:
            # Decide how to handle edited messages - log or process?
            message_content = update_data["edited_message"]
            update_type = "edited_message"
            logger.info(f"Received edited message for token {token[:4]}... (processing as regular message)")
        elif "callback_query" in update_data:
            # TODO: Implement callback query handling if needed
            logger.info(f"Received callback query for token {token[:4]}...: {update_data['callback_query'].get('data')}")
            # Often needs an immediate response (answerCallbackQuery)
            # For now, just log it and don't process further.
            return 
        elif "inline_query" in update_data:
            # TODO: Implement inline query handling if needed
            logger.info(f"Received inline query for token {token[:4]}...")
            return
        # Add other update types as needed (channel_post, etc.)

        if message_content:
             # Add the bot token to the context if not easily derived from message
             # Note: The message itself might contain bot info if it's a command
             message_content['_received_via_token'] = token 
             
             # Submit the extracted message content for processing
             asyncio.create_task(self.worker_pool.submit_monitor_task(
                 self._process_message,
                 message_content # Pass the inner message object
             ))
        else:
            logger.warning(f"Received webhook update for {token[:4]}... with unhandled type or no content: {list(update_data.keys())}")

    async def register_webhooks(self, base_webhook_url: str):
        """Registers webhooks with Telegram for all active bots using usernames."""
        logger.info(f"Attempting to register webhooks with base URL: {base_webhook_url}")
        
        active_bots = [] # Default to empty list
        # Fetch active bots (username and token) from MongoDB
        try:
            active_bots = await self.mongo_manager.get_active_bots() # Updated call
            if not active_bots:
                logger.warning("MongoDB returned no active bots to register webhooks for.")
        except PyMongoError as e:
            logger.error(f"Database error fetching active bots: {e}", exc_info=True)
            active_bots = [] 
        except Exception as e:
            logger.error(f"Unexpected error fetching active bots: {e}", exc_info=True)
            active_bots = []

        if not active_bots:
             logger.warning("No active bots found or fetched. Cannot register webhooks.")
             return # Exit if no bots

        async with aiohttp.ClientSession() as session:
            for bot in active_bots: # Loop through bot dictionaries
                token = bot.get("token")
                username = bot.get("username")

                if not token or ':' not in token or not username:
                    logger.warning(f"Skipping invalid bot data: {bot}")
                    continue
                
                webhook_endpoint = f"/{username}"
                full_webhook_url = base_webhook_url.rstrip('/') + webhook_endpoint
                api_url = f"https://api.telegram.org/bot{token}/setWebhook"
                payload = {"url": full_webhook_url}

                # --- Retry Logic for setWebhook --- 
                max_retries = 3
                base_delay = 1.0 # seconds
                attempt = 0
                success = False
                while attempt < max_retries and not success:
                    attempt += 1
                    try:
                        logger.info(f"Attempt {attempt}/{max_retries} to set webhook for bot '{username}' (token prefix: {token[:6]}) to URL: {full_webhook_url}")
                        async with session.post(api_url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as response:
                            resp_text = await response.text() # Read text first for better error parsing
                            try:
                                resp_json = json.loads(resp_text) # Try parsing JSON
                            except json.JSONDecodeError:
                                resp_json = {} # Use empty dict if not JSON
                                logger.warning(f"Non-JSON response received from Telegram for {username} (Status: {response.status}): {resp_text[:200]}...")

                            if response.status == 200 and resp_json.get("ok"):
                                logger.info(f"Successfully set webhook for bot '{username}' to {full_webhook_url}. Telegram says: {resp_json.get('description')}")
                                success = True # Mark as success to break loop
                            elif response.status == 429: # Rate limit error
                                retry_after = int(resp_json.get("parameters", {}).get("retry_after", base_delay * (2 ** (attempt - 1))))
                                wait_time = min(retry_after, 60) + (0.5 * attempt) # Use retry_after, cap it, add jitter
                                logger.warning(f"Rate limit hit (429) for bot '{username}'. Retrying attempt {attempt+1}/{max_retries} after {wait_time:.2f} seconds.")
                                await asyncio.sleep(wait_time)
                            else:
                                error_desc = resp_json.get("description", resp_text) # Use text if no description
                                logger.error(f"Failed to set webhook for bot '{username}' (Attempt {attempt}/{max_retries}). Status: {response.status}, Error: {error_desc}")
                                # Break on non-429 errors unless you want to retry other errors too
                                break # Stop retrying for this bot on other errors

                    except asyncio.TimeoutError:
                         logger.error(f"Timeout during attempt {attempt}/{max_retries} to set webhook for bot '{username}' at {full_webhook_url}")
                         if attempt < max_retries: await asyncio.sleep(base_delay * (2 ** attempt))
                    except aiohttp.ClientError as e:
                        logger.error(f"HTTP Client error setting webhook for bot '{username}' (Attempt {attempt}/{max_retries}): {e}")
                        if attempt < max_retries: await asyncio.sleep(base_delay * (2 ** attempt))
                    except Exception as e:
                        logger.error(f"Unexpected error setting webhook for bot '{username}' (Attempt {attempt}/{max_retries}): {e}", exc_info=True)
                        # Stop retrying on unexpected errors
                        break 
                # --- End Retry Logic ---
                
                if not success:
                     logger.error(f"Failed to set webhook for bot '{username}' after {max_retries} attempts.")

        # Start statistics reporting task after webhooks are set (or attempted)
        if not self.stats_task or self.stats_task.done():
            logger.info("Starting periodic statistics reporting.")
            self.stats_task = asyncio.create_task(self._report_stats_periodically())

    # --- End Webhook Handling ---

    async def _handle_telegram_message(self, message_data: Dict[str, Any]):
        """
        Handle a message received from Telegram (via polling - likely unused now).
        
        This was the callback for the TelegramMonitor polling mechanism.
        
        Args:
            message_data: Raw message data (Now could be the inner message dict)
        """
        bot_identifier = "unknown bot" # Define before try block
        try:
            # Adaption: If message_data contains the token, use it.
            # Otherwise, parsing logic needs to find bot context internally.
            bot_token = message_data.pop('_received_via_token', None)
            bot_identifier = f"token {bot_token[:4]}..." if bot_token else "unknown bot"

            # Parse the message (assuming message_data is now the inner message dict)
            parsed_data = self.message_parser.parse_message(message_data)
            
            # Add token info if we have it (may override parser's findings)
            if bot_token:
                 parsed_data['bot_token_used'] = bot_token
                 # We might need to map token to bot_id/username if parser fails

            # Check for high-value data
            if parsed_data.get("value_score", 0) > 70:
                logger.info(f"High-value data detected (score: {parsed_data.get('value_score')}) from {bot_identifier}")
            
            # Log the activity
            await self._log_activity(parsed_data)
            
            # Process extracted data
            await self._process_extracted_data(parsed_data)
            
            # Correlate data
            if parsed_data.get("bot_id"):
                asyncio.create_task(
                    self.elastic_manager.correlate_data(parsed_data["bot_id"])
                )
        except Exception as e:
            logger.error(f"Failed to process message from {bot_identifier}: {str(e)}", exc_info=True)
            
    async def _process_message(self, message_data: Dict[str, Any]):
        """
        Process a message.
        
        Args:
            message_data: Raw message data (Now could be the inner message dict)
        """
        bot_identifier = "unknown bot" # Define before try block
        try:
            # Parse the message
            parsed_data = self.message_parser.parse_message(message_data)
            
            # Check for high-value data
            if parsed_data.get("value_score", 0) > 70:
                logger.info(f"High-value data detected (score: {parsed_data.get('value_score')}) from {bot_identifier}")
            
            # Log the activity
            await self._log_activity(parsed_data)
            
            # Process extracted data
            await self._process_extracted_data(parsed_data)
            
            # Correlate data
            if parsed_data.get("bot_id"):
                asyncio.create_task(
                    self.elastic_manager.correlate_data(parsed_data["bot_id"])
                )
        except Exception as e:
            logger.error(f"Failed to process message: {str(e)}", exc_info=True)
            
    async def _log_activity(self, parsed_data: Dict[str, Any]):
        """
        Log bot activity.
        
        Args:
            parsed_data: Parsed message data
        """
        try:
            # Create log entry
            log_data = {
                "bot_id": parsed_data.get("bot_id"),
                "bot_username": parsed_data.get("bot_username"),
                "message_id": parsed_data.get("message_id"),
                "timestamp": datetime.utcnow(),
                "event_type": "message_received",
                "details": f"Received message with {len(parsed_data.get('credentials', []))} credentials, "
                          f"{len(parsed_data.get('cookies', []))} cookies, and "
                          f"{'some' if parsed_data.get('system_info') else 'no'} system info"
            }
            
            # Log to MongoDB
            await self.mongo_manager.log_activity(log_data)
            
            # Log to Elasticsearch if available
            try:
                await self.elastic_manager.log_activity(log_data)
            except Exception as e:
                logger.debug(f"Failed to log to Elasticsearch: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to log activity: {str(e)}")
            
    async def _process_extracted_data(self, parsed_data: Dict[str, Any]):
        """
        Process extracted data from a message.
        
        Args:
            parsed_data: Parsed message data
        """
        try:
            # Process credentials
            for credential in parsed_data.get("credentials", []):
                # Add metadata
                credential["bot_id"] = parsed_data.get("bot_id")
                credential["bot_username"] = parsed_data.get("bot_username")
                credential["message_id"] = parsed_data.get("message_id")
                credential["timestamp"] = datetime.utcnow()
                
                # Store in MongoDB
                await self.mongo_manager.store_credential(credential)
                
                # Store in Elasticsearch if available
                try:
                    await self.elastic_manager.index_credential(credential)
                except Exception as e:
                    logger.debug(f"Failed to index credential in Elasticsearch: {str(e)}")
                    
            # Process cookies
            for cookie in parsed_data.get("cookies", []):
                # Add metadata
                cookie["bot_id"] = parsed_data.get("bot_id")
                cookie["bot_username"] = parsed_data.get("bot_username")
                cookie["message_id"] = parsed_data.get("message_id")
                cookie["timestamp"] = datetime.utcnow()
                
                # Store in MongoDB
                await self.mongo_manager.store_cookie(cookie)
                
                # Store in Elasticsearch if available
                try:
                    await self.elastic_manager.index_cookie(cookie)
                except Exception as e:
                    logger.debug(f"Failed to index cookie in Elasticsearch: {str(e)}")
                    
            # Process system info
            system_info = parsed_data.get("system_info", {})
            if system_info:
                # Add metadata
                system_info["bot_id"] = parsed_data.get("bot_id")
                system_info["bot_username"] = parsed_data.get("bot_username")
                system_info["message_id"] = parsed_data.get("message_id")
                system_info["timestamp"] = datetime.utcnow()
                
                # Store in MongoDB
                await self.mongo_manager.store_system_info(system_info)
                
                # Store in Elasticsearch if available
                try:
                    await self.elastic_manager.index_system_info(system_info)
                except Exception as e:
                    logger.debug(f"Failed to index system info in Elasticsearch: {str(e)}")
                    
            # Process files
            for file_path in parsed_data.get("file_paths", []):
                if os.path.exists(file_path):
                    # Read file data
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                        
                    # Create metadata
                    metadata = {
                        "bot_id": parsed_data.get("bot_id"),
                        "bot_username": parsed_data.get("bot_username"),
                        "message_id": parsed_data.get("message_id"),
                        "timestamp": datetime.utcnow(),
                        "filename": os.path.basename(file_path)
                    }
                    
                    # Store in MongoDB GridFS
                    await self.mongo_manager.store_file(
                        file_data,
                        os.path.basename(file_path),
                        metadata
                    )
                    
        except asyncio.CancelledError:
            # Task was cancelled, exit gracefully
            logger.debug("Process extracted data task cancelled")
        except Exception as e:
            logger.error(f"Error in process extracted data: {str(e)}", exc_info=True)

    async def _report_stats_periodically(self):
        """Periodically report statistics."""
        while True:
            now = datetime.now()
            if (now - self.last_stats_report).total_seconds() >= self.stats_report_interval:
                # Generate and log stats
                # Placeholder for actual stats implementation
                logger.info("Reporting periodic stats (placeholder)")
                self.last_stats_report = now
                
            # Sleep for a shorter interval to check time
            await asyncio.sleep(60) # Check every minute