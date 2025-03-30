"""
Configuration settings for the Bot-Command application.
"""

import os
from typing import List, Optional
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Helper function to parse boolean environment variables consistently
def parse_bool_env(env_var_name, default="false"):
    """Parse boolean environment variable."""
    value = os.getenv(env_var_name, default).lower()
    return value not in ["false", "0", "no", "n", "f"]

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
    monitor_all_bots: bool = Field(default=parse_bool_env("MONITOR_ALL_BOTS", "false"), description="Monitor all bots encountered")
    filter_by_patterns: bool = Field(default=parse_bool_env("FILTER_BY_PATTERNS", "true"), description="Use patterns to identify stealer bots")
    phone_number: Optional[str] = Field(default=None, description="Phone number for Telegram account")
    session_name: str = Field(default="bot_command_session", description="Session name for Telegram client")
    media_retention_days: int = Field(
        default=int(os.getenv("MEDIA_RETENTION_DAYS", "30")),
        description="Number of days to retain downloaded media files"
    )
    max_disk_usage_gb: float = Field(
        default=float(os.getenv("MAX_DISK_USAGE_GB", "10")),
        description="Maximum disk space (GB) allowed for media downloads"
    )
    webhook_base_url: Optional[str] = Field(
        default=os.getenv("WEBHOOK_BASE_URL"),
        description="Base URL for receiving Telegram webhook updates (optional)"
    )

# Elasticsearch settings
class ElasticsearchConfig(BaseModel):
    uri: str = Field(
        default=os.getenv("ELASTICSEARCH_URI", "https://localhost:9200"),
        description="Elasticsearch connection URI"
    )
    username: Optional[str] = Field(
        default=os.getenv("ELASTICSEARCH_USERNAME"), 
        description="Elasticsearch username for basic auth (optional)"
    )
    password: Optional[str] = Field(
        default=os.getenv("ELASTICSEARCH_PASSWORD"), 
        description="Elasticsearch password for basic auth (optional)"
    )
    verify_certs: bool = Field(
        default=parse_bool_env("ELASTICSEARCH_VERIFY_CERTS"),
        description="Verify Elasticsearch TLS certificate"
    )
    ca_certs: Optional[str] = Field(
        default=os.getenv("ELASTICSEARCH_CA_CERTS"),
        description="Path to CA certificate for Elasticsearch SSL verification"
    )
    kibana_uri: str = Field(
        default=os.getenv("KIBANA_URI", "https://localhost:5601"), 
        description="Kibana connection URI"
    )
    index_prefix: str = Field(default="bot-command", description="Prefix for Elasticsearch indices")

# Main application config
class AppConfig(BaseModel):
    log_level: str = Field(
        default=os.getenv("LOG_LEVEL", "INFO").upper(), 
        description="Logging level (e.g., DEBUG, INFO, WARNING)"
    )
    debug: bool = Field(default=False, description="Enable debug mode")
    worker_pools: WorkerPoolConfig = Field(default_factory=WorkerPoolConfig)
    mongodb: MongoDBConfig = Field(default_factory=MongoDBConfig)
    telegram: TelegramConfig = Field(
        default_factory=lambda: TelegramConfig(
            api_id=int(os.getenv("TELEGRAM_API_ID", 0)),
            api_hash=os.getenv("TELEGRAM_API_HASH", ""),
            bot_usernames=os.getenv("TELEGRAM_BOT_USERNAMES", "").split(",") if os.getenv("TELEGRAM_BOT_USERNAMES") else [],
            bot_blocklist=os.getenv("TELEGRAM_BOT_BLOCKLIST", "").split(",") if os.getenv("TELEGRAM_BOT_BLOCKLIST") else [],
            phone_number=os.getenv("TELEGRAM_PHONE_NUMBER"),
            session_name=os.getenv("TELEGRAM_SESSION_NAME", "bot_monitor_session"),
            media_retention_days=int(os.getenv("MEDIA_RETENTION_DAYS", "30")),
            max_disk_usage_gb=float(os.getenv("MAX_DISK_USAGE_GB", "10")),
            webhook_base_url=os.getenv("WEBHOOK_BASE_URL")
        )
    )
    elasticsearch: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)

# Load configuration
def load_config() -> AppConfig:
    """Load environment variables and then application configuration."""
    # Load .env file FIRST, overriding any existing system env vars
    loaded = load_dotenv(override=True) 
    if loaded:
        print("Loaded environment variables from .env file, overriding system variables if conflicts existed.") # Optional: confirmation message
    # Then, initialize AppConfig which reads from the now-loaded env vars
    return AppConfig()

# Global config instance
config = load_config()

# --- Debug Print --- 
# Print the values loaded into the config object to verify .env loading
print(f"DEBUG [settings.py]: Loaded ES Username: '{config.elasticsearch.username}'")
print(f"DEBUG [settings.py]: Loaded ES Password is set: {bool(config.elasticsearch.password)}")
print(f"DEBUG [settings.py]: Raw ELASTICSEARCH_VERIFY_CERTS from env: '{os.getenv('ELASTICSEARCH_VERIFY_CERTS')}'")
print(f"DEBUG [settings.py]: Parsed to boolean: {parse_bool_env('ELASTICSEARCH_VERIFY_CERTS')}")
print(f"DEBUG [settings.py]: Final config ES verify_certs: {config.elasticsearch.verify_certs}")
print(f"DEBUG [settings.py]: MONITOR_ALL_BOTS from env: '{os.getenv('MONITOR_ALL_BOTS')}' -> {config.telegram.monitor_all_bots}")
print(f"DEBUG [settings.py]: FILTER_BY_PATTERNS from env: '{os.getenv('FILTER_BY_PATTERNS')}' -> {config.telegram.filter_by_patterns}")
# --- End Debug Print ---
