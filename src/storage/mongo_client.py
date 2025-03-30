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

logger = logging.getLogger(__name__)

class MongoDBManager:
    """Manages MongoDB connections and operations."""
    
    def __init__(self):
        """Initialize MongoDB manager."""
        self.config = config.mongodb
        
        # --- DEBUG: Print the URI being used ---
        print(f"DEBUG [mongo_client]: Attempting to connect with URI: {self.config.uri}")
        logger.debug(f"Attempting to connect with URI: {self.config.uri}") # Also log it
        # --- END DEBUG ---
        
        # Synchronous client for initialization and index creation
        # Explicitly pass the URI again for debugging
        print(f"DEBUG [mongo_client]: Initializing sync_client with URI: {self.config.uri}")
        self.sync_client = MongoClient(self.config.uri)
        self.sync_db = self.sync_client[self.config.database]
        
        # Asynchronous client for operations
        # Explicitly pass the URI again for debugging
        print(f"DEBUG [mongo_client]: Initializing async_client with URI: {self.config.uri}")
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
        self.monitored_bots = self.async_db[self.config.bot_collection]  # New collection for bot tokens
        
        # Set up indexes
        self._setup_indexes()
        
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
                logger.warning(f"Error dropping existing bot collection indexes: {str(e)}")
            
            # Create new bot collection indexes
            bot_collection.create_indexes([
                IndexModel([("token", ASCENDING)], unique=True, name="token_unique"),
                IndexModel([("username", ASCENDING)], unique=True, name="username_unique"),
                IndexModel([("status", ASCENDING)], name="status_index"),
                IndexModel([("last_checked", ASCENDING)], name="last_checked_index"),
                IndexModel([("failure_count", ASCENDING)], name="failure_count_index")
            ])
            
            logger.info("MongoDB indexes created successfully")
        except PyMongoError as e:
            logger.error(f"Failed to create MongoDB indexes: {str(e)}")
            raise
            
    async def store_credential(self, credential_data: Dict[str, Any]) -> str:
        """
        Store intercepted credential in MongoDB.
        
        Args:
            credential_data: Dictionary containing credential information
            
        Returns:
            ID of the inserted document
        """
        # Ensure timestamp field
        if "timestamp" not in credential_data:
            credential_data["timestamp"] = datetime.utcnow()
            
        try:
            result = await self.credentials.insert_one(credential_data)
            logger.debug(f"Stored credential with ID {result.inserted_id}")
            return str(result.inserted_id)
        except PyMongoError as e:
            logger.error(f"Failed to store credential: {str(e)}")
            raise
            
    async def store_cookie(self, cookie_data: Dict[str, Any]) -> str:
        """
        Store intercepted cookie in MongoDB.
        
        Args:
            cookie_data: Dictionary containing cookie information
            
        Returns:
            ID of the inserted document
        """
        # Ensure timestamp field
        if "timestamp" not in cookie_data:
            cookie_data["timestamp"] = datetime.utcnow()
            
        try:
            result = await self.cookies.insert_one(cookie_data)
            logger.debug(f"Stored cookie with ID {result.inserted_id}")
            return str(result.inserted_id)
        except PyMongoError as e:
            logger.error(f"Failed to store cookie: {str(e)}")
            raise
            
    async def store_system_info(self, system_data: Dict[str, Any]) -> str:
        """
        Store intercepted system information in MongoDB.
        
        Args:
            system_data: Dictionary containing system information
            
        Returns:
            ID of the inserted document
        """
        # Ensure timestamp field
        if "timestamp" not in system_data:
            system_data["timestamp"] = datetime.utcnow()
            
        try:
            result = await self.system_info.insert_one(system_data)
            logger.debug(f"Stored system info with ID {result.inserted_id}")
            return str(result.inserted_id)
        except PyMongoError as e:
            logger.error(f"Failed to store system info: {str(e)}")
            raise
            
    async def store_file(self, file_data: bytes, filename: str, 
                        metadata: Dict[str, Any]) -> str:
        """
        Store intercepted file in GridFS.
        
        Args:
            file_data: Binary file data
            filename: Name of the file
            metadata: Additional metadata for the file
            
        Returns:
            ID of the inserted file
        """
        try:
            # Add timestamp to metadata
            if "timestamp" not in metadata:
                metadata["timestamp"] = datetime.utcnow()
                
            file_id = await self.async_fs.upload_from_stream(
                filename, 
                file_data,
                metadata=metadata
            )
            logger.debug(f"Stored file with ID {file_id}")
            return str(file_id)
        except PyMongoError as e:
            logger.error(f"Failed to store file: {str(e)}")
            raise
            
    async def log_activity(self, log_data: Dict[str, Any]) -> str:
        """
        Log bot activity in MongoDB.
        
        Args:
            log_data: Dictionary containing log information
            
        Returns:
            ID of the inserted document
        """
        # Ensure timestamp field
        if "timestamp" not in log_data:
            log_data["timestamp"] = datetime.utcnow()
            
        try:
            result = await self.logs.insert_one(log_data)
            logger.debug(f"Logged activity with ID {result.inserted_id}")
            return str(result.inserted_id)
        except PyMongoError as e:
            logger.error(f"Failed to log activity: {str(e)}")
            raise
            
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
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            cursor = self.logs.find({
                "bot_id": bot_id,
                "timestamp": {"$gte": start_time}
            }).sort("timestamp", DESCENDING)
            
            return await cursor.to_list(length=None)
        except PyMongoError as e:
            logger.error(f"Failed to get bot activity: {str(e)}")
            raise
            
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
        query = {}
        if domain:
            query["domain"] = domain
        if username:
            query["username"] = username
            
        try:
            cursor = self.credentials.find(query).sort("timestamp", DESCENDING).limit(100)
            return await cursor.to_list(length=None)
        except PyMongoError as e:
            logger.error(f"Failed to search credentials: {str(e)}")
            raise
            
    async def store_parser_stats(self, stats_data: Dict[str, Any]) -> str:
        """
        Store parser statistics in MongoDB.
        
        Args:
            stats_data: Dictionary containing parser statistics
            
        Returns:
            ID of the inserted document
        """
        # Create statistics document
        stats_doc = {
            "type": "parser_stats",
            "timestamp": datetime.utcnow(),
            "data": stats_data
        }
        
        try:
            result = await self.stats.insert_one(stats_doc)
            logger.debug(f"Stored parser stats with ID {result.inserted_id}")
            return str(result.inserted_id)
        except PyMongoError as e:
            logger.error(f"Failed to store parser stats: {str(e)}")
            raise
            
    async def get_parser_stats_history(self, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Get historical parser statistics.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            List of parser stats documents
        """
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            cursor = self.stats.find({
                "type": "parser_stats",
                "timestamp": {"$gte": start_time}
            }).sort("timestamp", ASCENDING)
            
            return await cursor.to_list(length=None)
        except PyMongoError as e:
            logger.error(f"Failed to get parser stats history: {str(e)}")
            raise
            
    async def get_credential_stats(self, hours: int = 24) -> Dict[str, Any]:
        """
        Get statistics on stolen credentials.
        
        Args:
            hours: Number of hours to look back
            
        Returns:
            Dictionary with credential statistics
        """
        try:
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
        except PyMongoError as e:
            logger.error(f"Failed to get credential stats: {str(e)}")
            raise
            
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
        try:
            now = datetime.utcnow()
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

    async def get_active_bots(self) -> List[Dict[str, str]]:
        """
        Get list of active bots with their usernames and tokens.
        
        Returns:
            List of dictionaries, each containing 'username' and 'token' for an active bot.
        """
        cursor = self.monitored_bots.find(
            {"status": "active", "username": {"$ne": None}},
            projection={"token": 1, "username": 1, "_id": 0}
        )
        bots = []
        async for doc in cursor:
            if "username" in doc and "token" in doc:
                bots.append({"username": doc["username"], "token": doc["token"]})
        return bots

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

    async def remove_bot_token(self, token: str) -> bool:
        """
        Remove a bot token from monitoring.
        
        Args:
            token: Bot token to remove
            
        Returns:
            bool: True if token was found and removed
        """
        result = await self.monitored_bots.delete_one({"token": token})
        return result.deleted_count > 0

    async def get_bot_info(self, token: Optional[str] = None, username: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Get information about a monitored bot.
        
        Args:
            token: Bot token (optional)
            username: Bot username (optional)
            
        Returns:
            Bot information or None if not found
        """
        if not token and not username:
            return None
            
        query = {}
        if token:
            query["token"] = token
        elif username:
            query["username"] = username
            
        return await self.monitored_bots.find_one(query)

    def close(self):
        """Close MongoDB connections."""
        self.sync_client.close()
        self.async_client.close()
