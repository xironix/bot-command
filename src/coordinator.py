"""
Main coordinator for the Bot-Command application.

This module orchestrates the various components of the application, including
Telegram monitoring, message processing, and data storage.
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import Dict, List, Any, Optional

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
        telegram_logger = logging.getLogger("telegram")
        telegram_logger.setLevel(logging.DEBUG)
        
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
        
    async def start_monitoring(self, bot_usernames: List[str] = None):
        """
        Start monitoring specified bots.
        
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
                await self.telegram_monitor.monitor_bot_channel(username)
                
        # Start statistics reporting task
        asyncio.create_task(self._report_stats_periodically())
                
        logger.info("Bot monitoring started")
        
    def _handle_telegram_message(self, message_data: Dict[str, Any]):
        """
        Handle a message received from Telegram.
        
        This is the callback that will be invoked by the TelegramMonitor when
        a new message is received.
        
        Args:
            message_data: Raw message data from Telegram
        """
        # Submit to the monitor queue for processing
        asyncio.create_task(self.worker_pool.submit_monitor_task(
            self._process_message,
            message_data
        ))
        
    async def _process_message(self, message_data: Dict[str, Any]):
        """
        Process a message.
        
        Args:
            message_data: Raw message data
        """
        try:
            # Parse the message
            parsed_data = self.message_parser.parse_message(message_data)
            
            # Check for high-value data
            if parsed_data.get("value_score", 0) > 70:
                logger.info(f"High-value data detected (score: {parsed_data.get('value_score')}) from bot {parsed_data.get('bot_username')}")
            
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
                    
    async def _report_stats_periodically(self):
        """
        Report parser statistics periodically.
        """
        try:
            while self.initialized:
                # Wait for the report interval
                await asyncio.sleep(self.stats_report_interval)
                
                # Get current time
                current_time = datetime.now()
                
                # Calculate time since last report
                time_since_last = (current_time - self.last_stats_report).total_seconds()
                
                # Skip if we haven't reached the interval yet
                if time_since_last < self.stats_report_interval:
                    continue
                    
                # Update last report time
                self.last_stats_report = current_time
                
                # Get parser stats - now an async method
                stats = await self.message_parser.get_parser_stats()
                
                # Log basic stats
                logger.info(f"Parser statistics: processed={stats['total_processed']}, "
                           f"success_rate={stats.get('overall_success_rate', 0):.2f}%, "
                           f"high_value_extractions={stats['high_value_extractions']}")
                
                # Log plugin-specific stats if we have successful parsing
                if stats["plugin_successes"] > 0:
                    # Sort plugins by success rate
                    plugin_stats = sorted(
                        [(name, data) for name, data in stats["plugins"].items() if data["attempts"] > 0],
                        key=lambda x: x[1].get("success_rate", 0),
                        reverse=True
                    )
                    
                    # Log top 3 plugins
                    for name, data in plugin_stats[:3]:
                        if data["attempts"] > 0:
                            logger.info(f"Top parser plugin: {name}, "
                                       f"success_rate={data.get('success_rate', 0):.2f}%, "
                                       f"avg_value_score={data.get('avg_value_score', 0):.2f}, "
                                       f"attempts={data['attempts']}")
                                       
                # Log to MongoDB for long-term tracking
                await self.mongo_manager.store_parser_stats(stats)
                
                # Also log to Elasticsearch if available
                try:
                    await self.elastic_manager.index_parser_stats(stats)
                except Exception as e:
                    logger.debug(f"Failed to index parser stats in Elasticsearch: {str(e)}")
                    
        except asyncio.CancelledError:
            # Task was cancelled, exit gracefully
            logger.debug("Stats reporting task cancelled")
        except Exception as e:
            logger.error(f"Error in stats reporting task: {str(e)}", exc_info=True)