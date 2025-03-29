"""
Main coordinator for the Bot-Command application.

This module orchestrates the various components of the application, including
Telegram monitoring, message processing, and data storage.
"""

import asyncio
import logging
import os
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
        
        # Initialize worker pool
        await self.worker_pool.start()
        
        # Initialize Elasticsearch (if available)
        elastic_available = await self.elastic_manager.initialize()
        if not elastic_available:
            logger.warning("Elasticsearch is not available, some features will be limited")
            
        # Initialize Telegram monitor
        await self.telegram_monitor.initialize()
        
        self.initialized = True
        logger.info("Bot-Command coordinator initialized")
        
    async def shutdown(self):
        """Shut down all components."""
        if not self.initialized:
            return
            
        logger.info("Shutting down Bot-Command coordinator")
        
        # Shut down worker pool
        await self.worker_pool.stop()
        
        # Close Telegram monitor
        await self.telegram_monitor.close()
        
        # Close Elasticsearch connection
        await self.elastic_manager.close()
        
        # Close MongoDB connection
        self.mongo_manager.close()
        
        self.initialized = False
        logger.info("Bot-Command coordinator shut down")
        
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
        """Registers webhooks with Telegram for all active bots."""
        logger.info(f"Attempting to register webhooks with base URL: {base_webhook_url}")
        
        active_tokens = [] # Default to empty list
        # Fetch active tokens from MongoDB
        try:
            active_tokens = await self.mongo_manager.get_active_bot_tokens() 
            if not active_tokens:
                logger.warning("MongoDB returned no active bot tokens to register webhooks for.")
        except PyMongoError as e: # Make sure PyMongoError is imported if not already
            logger.error(f"Database error fetching active bot tokens: {e}", exc_info=True)
            # Decide if we should proceed without tokens or raise/exit
            active_tokens = [] # Ensure it's empty on error
        except Exception as e:
            logger.error(f"Unexpected error fetching active bot tokens: {e}", exc_info=True)
            active_tokens = [] # Ensure it's empty on error

        if not active_tokens:
             logger.warning("No active bot tokens found or fetched. Cannot register webhooks.")
             # Potentially start stats task anyway?
             # if not self.stats_task or self.stats_task.done():
             #    logger.info("Starting periodic statistics reporting (no webhooks registered).")
             #    self.stats_task = asyncio.create_task(self._report_stats_periodically())
             return # Exit if no tokens

        async with aiohttp.ClientSession() as session:
            for token in active_tokens:
                if not token or ':' not in token: # Basic validation
                    logger.warning(f"Skipping invalid token format: {token[:10]}...")
                    continue
                
                webhook_endpoint = f"/webhook/{token}" # Define specific path per token
                full_webhook_url = base_webhook_url.rstrip('/') + webhook_endpoint
                api_url = f"https://api.telegram.org/bot{token}/setWebhook"
                
                payload = {"url": full_webhook_url}
                # Optional: Add allowed_updates, drop_pending_updates, secret_token etc.
                # payload["allowed_updates"] = ["message", "edited_message", ...]
                # payload["drop_pending_updates"] = True
                
                try:
                    logger.info(f"Setting webhook for token {token[:4]}... to {full_webhook_url}")
                    async with session.post(api_url, json=payload) as response:
                        resp_json = await response.json()
                        if response.status == 200 and resp_json.get("ok"):
                            logger.info(f"Successfully set webhook for token {token[:4]}... Result: {resp_json.get('description')}")
                        else:
                            error_desc = resp_json.get("description", "Unknown error")
                            logger.error(f"Failed to set webhook for token {token[:4]}... Status: {response.status}, Error: {error_desc}")
                except aiohttp.ClientError as e:
                    logger.error(f"HTTP Client error setting webhook for token {token[:4]}...: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error setting webhook for token {token[:4]}...: {e}", exc_info=True)

        # Start statistics reporting task after webhooks are set
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