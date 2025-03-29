"""
Configuration settings for the Bot-Command application.
"""

import os
from typing import List, Optional
from pydantic import BaseModel, Field

# Worker pool settings
class WorkerPoolConfig(BaseModel):
    monitor_workers: int = Field(default=5, description="Number of workers for bot monitoring")
    download_workers: int = Field(default=5, description="Number of workers for file downloads")
    database_workers: int = Field(default=5, description="Number of workers for database operations")

# MongoDB settings
class MongoDBConfig(BaseModel):
    uri: str = Field(
        default=os.getenv("MONGODB_URI", "mongodb://localhost:27017/"),
        description="MongoDB connection URI"
    )
    database: str = Field(default="bot_command", description="Database name")
    credential_collection: str = Field(default="credentials", description="Collection for stolen credentials")
    cookie_collection: str = Field(default="cookies", description="Collection for stolen cookies")
    system_info_collection: str = Field(default="system_info", description="Collection for system information")
    log_collection: str = Field(default="logs", description="Collection for activity logs")
    bot_collection: str = Field(default="monitored_bots", description="Collection for monitored bot tokens")
    ttl_days: int = Field(default=30, description="Days to keep data before expiration")

# Telegram API settings
class TelegramConfig(BaseModel):
    api_id: int = Field(description="Telegram API ID")
    api_hash: str = Field(description="Telegram API hash")
    bot_usernames: List[str] = Field(default=[], description="List of Telegram bot usernames to explicitly monitor (auto-populated from tokens)")
    bot_blocklist: List[str] = Field(default=[], description="List of Telegram bot usernames to ignore")
    monitor_all_bots: bool = Field(default=False, description="Monitor all bots encountered")
    filter_by_patterns: bool = Field(default=True, description="Use patterns to identify stealer bots")
    phone_number: Optional[str] = Field(default=None, description="Phone number for Telegram account")
    session_name: str = Field(default="bot_command_session", description="Session name for Telegram client")

# Elasticsearch settings
class ElasticsearchConfig(BaseModel):
    uri: str = Field(
        default=os.getenv("ELASTICSEARCH_URI", "https://localhost:9200"),
        description="Elasticsearch connection URI"
    )
    kibana_uri: str = Field(default="http://localhost:5601", description="Kibana connection URI")
    index_prefix: str = Field(default="bot-command", description="Prefix for Elasticsearch indices")

# Main application config
class AppConfig(BaseModel):
    debug: bool = Field(default=False, description="Enable debug mode")
    worker_pools: WorkerPoolConfig = Field(default_factory=WorkerPoolConfig)
    mongodb: MongoDBConfig = Field(default_factory=MongoDBConfig)
    telegram: TelegramConfig = Field(
        default_factory=lambda: TelegramConfig(
            api_id=int(os.getenv("TELEGRAM_API_ID", "0")),
            api_hash=os.getenv("TELEGRAM_API_HASH", ""),
            bot_usernames=os.getenv("TELEGRAM_BOT_USERNAMES", "").split(",") if os.getenv("TELEGRAM_BOT_USERNAMES") else [],
            bot_blocklist=os.getenv("TELEGRAM_BOT_BLOCKLIST", "").split(",") if os.getenv("TELEGRAM_BOT_BLOCKLIST") else [],
            monitor_all_bots=os.getenv("MONITOR_ALL_BOTS", "").lower() == "true",
            filter_by_patterns=os.getenv("FILTER_BY_PATTERNS", "true").lower() == "true",
            phone_number=os.getenv("TELEGRAM_PHONE_NUMBER"),
            session_name=os.getenv("TELEGRAM_SESSION_NAME", "bot_monitor_session")
        )
    )
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)

# Load configuration
def load_config() -> AppConfig:
    """Load application configuration from environment variables."""
    return AppConfig()

# Global config instance
config = load_config()
