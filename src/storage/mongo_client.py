"""
MongoDB client and operations for the Bot-Command application.

This module handles connections to MongoDB and provides methods for storing
and retrieving intercepted data from stealer bots.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

import motor.motor_asyncio
from pymongo import MongoClient, IndexModel, ASCENDING, DESCENDING, HASHED, TEXT
from pymongo.errors import PyMongoError
import gridfs

from config.settings import config
from src.utils.base_client import BaseAsyncClient
from src.utils.error_handler import RetryHandler, ErrorLogger

class MongoDBManager(BaseAsyncClient):
    """Manages MongoDB connections and operations."""
    
    def __init__(self):
        """Initialize MongoDB manager."""
        super().__init__("mongodb_manager")
        self.config = config.mongodb
        
        # Initialize client attributes
        self.sync_client = None
        self.sync_db = None
        self.async_client = None
        self.async_db = None
        self.fs = None
        self.async_fs = None
        
        # Initialize collection attributes
        self.credentials = None
        self.cookies = None
        self.system_info = None
        self.logs = None
        self.stats = None
        self.monitored_bots = None
        
    async def _initialize_client(self) -> bool:
        """
        Initialize MongoDB client connections.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        try:
            # Debug info
            self.logger.debug(f"Attempting to connect with URI: {self.config.uri}")
            
            # Synchronous client for initialization and index creation
            self.sync_client = MongoClient(self.config.uri)
            self.sync_db = self.sync_client[self.config.database]
            
            # Asynchronous client for operations
            self.async_client = motor.motor_asyncio.AsyncIOMotorClient(self.config.uri)
            self.async_db = self.async_client[self.config.database]
            
            # GridFS for file storage
            self.fs = gridfs.GridFS(self.sync_db)
            self.async_fs = motor.motor_asyncio.AsyncIOMotorGridFSBucket(self.async_db)
            
            # Initialize collections
            self.credentials = self.async_db[self.config.credential_collection]
            self.cookies = self.async_db[self.config.cookie_collection]
            self.system_info = self.async_db[self.config.system_info_collection]
            self.logs = self.async_db[self.config.log_collection]
            self.stats = self.async_db["parser_stats"]  # Collection for parser statistics
            self.monitored_bots = self.async_db[self.config.bot_collection]  # Collection for bot tokens
            
            # Set up indexes
            self._setup_indexes()
            
            # Test connection
            try:
                # Ping database
                await self.async_db.command("ping")
                self.logger.info("MongoDB connection successful")
                return True
            except Exception as e:
                self.logger.error(f"MongoDB ping failed: {e}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to initialize MongoDB: {str(e)}", exc_info=True)
            return False
            
    async def _shutdown_client(self) -> None:
        """Shutdown MongoDB client connections."""
        try:
            if self.sync_client:
                self.sync_client.close()
                
            if self.async_client:
                self.async_client.close()
                
            self.logger.info("MongoDB connections closed")
        except Exception as e:
            self.logger.error(f"Error closing MongoDB connections: {str(e)}")
            
    def get_status(self) -> Dict[str, Any]:
        """
        Get MongoDB client status information.
        
        Returns:
            Dictionary with status information
        """
        status = {
            "name": self.name,
            "initialized": self.initialized,
            "uri": self.config.uri,
            "database": self.config.database,
            "collections": {
                "credentials": self.config.credential_collection,
                "cookies": self.config.cookie_collection,
                "system_info": self.config.system_info_collection,
                "logs": self.config.log_collection,
                "bots": self.config.bot_collection
            }
        }
        return status
        
    def _setup_indexes(self):
        """Set up optimized indexes for MongoDB collections."""
        try:
            # Credentials collection indexes
            self.sync_db[self.config.credential_collection].create_indexes([
                IndexModel([("username", ASCENDING), ("domain", ASCENDING)], 
                           name="credential_search"),
                IndexModel([("bot_id", HASHED)], name="shard_key"),
                IndexModel([("timestamp", ASCENDING)], name="time_index"),
                IndexModel([("source_ip", ASCENDING)], name="ip_index")
            ])
            
            # Parser stats collection indexes
            self.sync_db["parser_stats"].create_indexes([
                IndexModel([("timestamp", DESCENDING)], name="time_index"),
                IndexModel([("type", ASCENDING)], name="type_index"),
                IndexModel([("timestamp", ASCENDING)], 
                          expireAfterSeconds=30 * 86400,  # 30 days TTL
                          name="stats_ttl")
            ])
            
            # Cookies collection indexes
            self.sync_db[self.config.cookie_collection].create_indexes([
                IndexModel([("domain", ASCENDING)], name="domain_index"),
                IndexModel([("bot_id", HASHED)], name="shard_key"),
                IndexModel([("timestamp", ASCENDING)], name="time_index")
            ])
            
            # System info collection indexes
            self.sync_db[self.config.system_info_collection].create_indexes([
                IndexModel([("bot_id", ASCENDING)], name="bot_id_index"),
                IndexModel([("description", TEXT)], name="text_search"),
                IndexModel([("timestamp", ASCENDING)], name="time_index")
            ])
            
            # Logs collection with TTL index
            self.sync_db[self.config.log_collection].create_indexes([
                IndexModel([("timestamp", ASCENDING)], 
                           expireAfterSeconds=self.config.ttl_days * 86400, 
                           name="logs_ttl")
            ])
            
            # Handle bot collection indexes separately
            bot_collection = self.sync_db[self.config.bot_collection]
            
            # Drop existing bot collection indexes (except _id)
            try:
                for index in bot_collection.list_indexes():
                    if index['name'] != '_id_':
                        bot_collection.drop_index(index['name'])
            except PyMongoError as e:
                self.logger.warning(f"Error dropping existing bot collection indexes: {str(e)}")
            
            # Create new bot collection indexes
            bot_collection.create_indexes([
                IndexModel([("token", ASCENDING)], unique=True, name="token_unique"),
                IndexModel([("username", ASCENDING)], unique=True, name="username_unique"),
                IndexModel([("status", ASCENDING)], name="status_index"),
                IndexModel([("last_checked", ASCENDING)], name="last_checked_index"),
                IndexModel([("failure_count", ASCENDING)], name="failure_count_index")
            ])
            
            self.logger.info("MongoDB indexes created successfully")
        except PyMongoError as e:
            self.logger.error(f"Failed to create MongoDB indexes: {str(e)}")
            raise
            
    @ErrorLogger.async_safe_operation(default_value=None, log_level=logging.WARNING)
    async def store_credential(self, credential_data: Dict[str, Any]) -> Optional[str]:
        """
        Store intercepted credential in MongoDB.
        
        Args:
            credential_data: Dictionary containing credential information
            
        Returns:
            ID of the inserted document
        """
        if not self.initialized:
            self.logger.warning("Cannot store credential - MongoDB is not initialized")
            return None
            
        # Ensure timestamp field
        if "timestamp" not in credential_data:
            credential_data["timestamp"] = datetime.utcnow()
            
        result = await self.credentials.insert_one(credential_data)
        self.logger.debug(f"Stored credential with ID {result.inserted_id}")
        return str(result.inserted_id)
            
    @ErrorLogger.async_safe_operation(default_value=None, log_level=logging.WARNING)
    async def store_cookie(self, cookie_data: Dict[str, Any]) -> Optional[str]:
        """
        Store intercepted cookie in MongoDB.
        
        Args:
            cookie_data: Dictionary containing cookie information
            
        Returns:
            ID of the inserted document
        """
        if not self.initialized:
            self.logger.warning("Cannot store cookie - MongoDB is not initialized")
            return None
            
        # Ensure timestamp field
        if "timestamp" not in cookie_data:
            cookie_data["timestamp"] = datetime.utcnow()
            
        result = await self.cookies.insert_one(cookie_data)
        self.logger.debug(f"Stored cookie with ID {result.inserted_id}")
        return str(result.inserted_id)
            
    @ErrorLogger.async_safe_operation(default_value=None, log_level=logging.WARNING)
    async def store_system_info(self, system_data: Dict[str, Any]) -> Optional[str]:
        """
        Store intercepted system information in MongoDB.
        
        Args:
            system_data: Dictionary containing system information
            
        Returns:
            ID of the inserted document
        """
        if not self.initialized:
            self.logger.warning("Cannot store system info - MongoDB is not initialized")
            return None
            
        # Ensure timestamp field
        if "timestamp" not in system_data:
            system_data["timestamp"] = datetime.utcnow()
            
        result = await self.system_info.insert_one(system_data)
        self.logger.debug(f"Stored system info with ID {result.inserted_id}")
        return str(result.inserted_id)
            
    @ErrorLogger.async_safe_operation(default_value=None, log_level=logging.WARNING)
    async def store_file(self, file_data: bytes, filename: str, 
                        metadata: Dict[str, Any]) -> Optional[str]:
        """
        Store intercepted file in GridFS.
        
        Args:
            file_data: Binary file data
            filename: Name of the file
            metadata: Additional metadata for the file
            
        Returns:
            ID of the inserted file
        """
        if not self.initialized:
            self.logger.warning("Cannot store file - MongoDB is not initialized")
            return None
            
        # Add timestamp to metadata
        if "timestamp" not in metadata:
            metadata["timestamp"] = datetime.utcnow()
            
        file_id = await self.async_fs.upload_from_stream(
            filename, 
            file_data,
            metadata=metadata
        )
        self.logger.debug(f"Stored file with ID {file_id}")
        return str(file_id)
            
    @ErrorLogger.async_safe_operation(default_value=None, log_level=logging.WARNING)
    async def log_activity(self, log_data: Dict[str, Any]) -> Optional[str]:
        """
        Log bot activity in MongoDB.
        
        Args:
            log_data: Dictionary containing log information
            
        Returns:
            ID of the inserted document
        """
        if not self.initialized:
            self.logger.warning("Cannot log activity - MongoDB is not initialized")
            return None
            
        # Ensure timestamp field
        if "timestamp" not in log_data:
            log_data["timestamp"] = datetime.utcnow()
            
        result = await self.logs.insert_one(log_data)
        self.logger.debug(f"Logged activity with ID {result.inserted_id}")
        return str(result.inserted_id)
            
    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def get_bot_activity(self, bot_id: str, 
                              hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get recent activity for a specific bot.
        
        Args:
            bot_id: ID of the bot
            hours: Number of hours to look back
            
        Returns:
            List of activity documents
        """
        if not self.initialized:
            self.logger.warning("Cannot get bot activity - MongoDB is not initialized")
            return []
            
        start_time = datetime.utcnow() - timedelta(hours=hours)
        cursor = self.logs.find({
            "bot_id": bot_id,
            "timestamp": {"$gte": start_time}
        }).sort("timestamp", DESCENDING)
        
        return await cursor.to_list(length=None)
            
    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def search_credentials(self, domain: Optional[str] = None, 
                                username: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search for credentials based on domain and/or username.
        
        Args:
            domain: Domain to search for
            username: Username to search for
            
        Returns:
            List of matching credential documents
        """
        if not self.initialized:
            self.logger.warning("Cannot search credentials - MongoDB is not initialized")
            return []
            
        query = {}
        if domain:
            query["domain"] = domain
        if username:
            query["username"] = username
            
        cursor = self.credentials.find(query).sort("timestamp", DESCENDING).limit(100)
        return await cursor.to_list(length=None)
            
    @ErrorLogger.async_safe_operation(default_value=None, log_level=logging.WARNING)
    async def store_parser_stats(self, stats_data: Dict[str, Any]) -> Optional[str]:
        """
        Store parser statistics in MongoDB.
        
        Args:
            stats_data: Dictionary containing parser statistics
            
        Returns:
            ID of the inserted document
        """
        if not self.initialized:
            self.logger.warning("Cannot store parser stats - MongoDB is not initialized")
            return None
            
        # Create statistics document
        stats_doc = {
            "type": "parser_stats",
            "timestamp": datetime.utcnow(),
            "data": stats_data
        }
        
        result = await self.stats.insert_one(stats_doc)
        self.logger.debug(f"Stored parser stats with ID {result.inserted_id}")
        return str(result.inserted_id)
            
    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def get_parser_stats_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get historical parser statistics.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of parser stats documents
        """
        if not self.initialized:
            self.logger.warning("Cannot get parser stats history - MongoDB is not initialized")
            return []
            
        start_time = datetime.utcnow() - timedelta(hours=hours)
        cursor = self.stats.find({
            "type": "parser_stats",
            "timestamp": {"$gte": start_time}
        }).sort("timestamp", ASCENDING)
        
        return await cursor.to_list(length=None)
            
    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def get_credential_stats(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get statistics on stolen credentials.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with credential statistics
        """
        if not self.initialized:
            self.logger.warning("Cannot get credential stats - MongoDB is not initialized")
            return {"total_count": 0, "top_domains": []}
            
        start_time = datetime.utcnow() - timedelta(hours=hours)
        
        # Get total count
        total_count = await self.credentials.count_documents({
            "timestamp": {"$gte": start_time}
        })
        
        # Get top domains
        pipeline = [
            {"$match": {"timestamp": {"$gte": start_time}}},
            {"$group": {"_id": "$domain", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        cursor = self.credentials.aggregate(pipeline)
        top_domains = await cursor.to_list(length=None)
        
        return {
            "total_count": total_count,
            "top_domains": top_domains
        }
            
    @ErrorLogger.async_safe_operation(default_value=False, log_level=logging.WARNING)
    async def add_bot_token(self, token: str, username: str, status: str = 'active') -> bool:
        """
        Add a new bot token to monitor.
        
        Args:
            token: Bot token
            username: Bot username
            status: Bot status ('active', 'logged_out', 'invalid', 'unauthorized')
            
        Returns:
            bool: True if successful, False if token already exists
        """
        if not self.initialized:
            self.logger.warning("Cannot add bot token - MongoDB is not initialized")
            return False
            
        now = datetime.utcnow()
        try:
            await self.monitored_bots.insert_one({
                "token": token,
                "username": username,
                "status": status,
                "added_at": now,
                "last_checked": now,
                "failure_count": 0 if status == 'active' else 1,
                "last_failure": now if status != 'active' else None,
                "last_success": now if status == 'active' else None
            })
            return True
        except PyMongoError as e:
            if "duplicate key" in str(e):
                return False
            raise

    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def get_active_bots(self) -> List[Dict[str, str]]:
        """
        Get list of active bots with their usernames and tokens.
        
        Returns:
            List of dictionaries, each containing 'username' and 'token' for an active bot.
        """
        if not self.initialized:
            self.logger.warning("Cannot get active bots - MongoDB is not initialized")
            return []
            
        cursor = self.monitored_bots.find(
            {"status": "active", "username": {"$ne": None}},
            projection={"token": 1, "username": 1, "_id": 0}
        )
        bots = []
        async for doc in cursor:
            if "username" in doc and "token" in doc:
                bots.append({"username": doc["username"], "token": doc["token"]})
        return bots

    @ErrorLogger.async_safe_operation(default_value=False, log_level=logging.WARNING)
    async def update_bot_status(self, token: str, *, 
                              status: Optional[str] = None,
                              username: Optional[str] = None,
                              increment_failures: bool = False,
                              success: bool = False) -> bool:
        """
        Update bot token status and metadata.
        
        Args:
            token: Bot token
            status: New status (active/inactive)
            username: Bot username to update
            increment_failures: Whether to increment failure count
            success: Whether to record successful check
            
        Returns:
            bool: True if update was successful
        """
        if not self.initialized:
            self.logger.warning("Cannot update bot status - MongoDB is not initialized")
            return False
            
        now = datetime.utcnow()
        update: Dict[str, Any] = {"$set": {"last_checked": now}}
        
        if status:
            update["$set"]["status"] = status
        
        if username:
            update["$set"]["username"] = username
            
        if increment_failures:
            update["$inc"] = {"failure_count": 1}
            update["$set"]["last_failure"] = now
        
        if success:
            if "$set" not in update:
                update["$set"] = {}
            update["$set"].update({
                "last_success": now,
                "failure_count": 0  # Reset failures on success
            })
            
        result = await self.monitored_bots.update_one(
            {"token": token},
            update
        )
        return result.modified_count > 0

    @ErrorLogger.async_safe_operation(default_value=False, log_level=logging.WARNING)
    async def remove_bot_token(self, token: str) -> bool:
        """
        Remove a bot token from monitoring.
        
        Args:
            token: Bot token to remove
            
        Returns:
            bool: True if token was found and removed
        """
        if not self.initialized:
            self.logger.warning("Cannot remove bot token - MongoDB is not initialized")
            return False
            
        result = await self.monitored_bots.delete_one({"token": token})
        return result.deleted_count > 0

    @RetryHandler.async_retry(max_retries=2, retry_delay=1.0)
    async def get_bot_info(self, token: Optional[str] = None, username: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get information about a monitored bot.
        
        Args:
            token: Bot token (optional)
            username: Bot username (optional)
            
        Returns:
            Bot information or None if not found
        """
        if not self.initialized:
            self.logger.warning("Cannot get bot info - MongoDB is not initialized")
            return None
            
        if not token and not username:
            return None
            
        query = {}
        if token:
            query["token"] = token
        elif username:
            query["username"] = username
            
        return await self.monitored_bots.find_one(query)
