#!/usr/bin/env python3
"""
Bot-Command - Covert Intelligence-Gathering Tool for Telegram Stealer Bots

This tool silently intercepts and replicates the data collection process of 
Telegram-based stealer bots without modifying their behavior or alerting operators.
"""

# Standard library imports first
import argparse
import logging
import os
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler
from contextlib import asynccontextmanager

# Third-party imports
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import uvicorn

# Load .env file BEFORE anything else reads environment variables
load_dotenv()

# Local application/library specific imports
from src.coordinator import Coordinator
# Import both the function and the global config object
from config.settings import load_config, config

# Add project root to the Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Parse command line arguments BEFORE loading configuration
def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Bot-Command Monitoring Tool")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    return parser.parse_args()

# Parse arguments
args = parse_arguments()

# Update config based on command line arguments
if args.debug:
    config.debug = True
    config.log_level = "DEBUG"
    print("Debug mode enabled via command line argument")

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Get log level from the config object
log_level = getattr(logging, config.log_level, logging.INFO)

# Configure rotating file handler
log_file = f"logs/bot_command_{datetime.now().strftime('%Y%m%d')}.log"
file_handler = RotatingFileHandler(
    log_file,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=10,
    encoding="utf-8"
)

# Set formatter for the file handler
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# Get the root logger
root_logger = logging.getLogger()
root_logger.setLevel(log_level) # Set the overall level

# Clear existing handlers
if root_logger.hasHandlers():
    root_logger.handlers.clear()

# Create RichHandler for console output
rich_handler = RichHandler(
    level=log_level, 
    show_time=True,
    show_level=True,
    show_path=False, 
    markup=True, 
    rich_tracebacks=True
)

# Add ONLY our configured handlers
root_logger.addHandler(rich_handler)
root_logger.addHandler(file_handler)

# Set specific log levels for noisy libraries
logging.getLogger("telethon").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)

# Get logger for this module AFTER logging is configured
logger = logging.getLogger(__name__)

# Log the effective level to confirm configuration
root_logger = logging.getLogger() # Get the root logger
logger.info(f"Effective logging level set to: {logging.getLevelName(root_logger.getEffectiveLevel())}")

# --- End Logging Configuration --- 

# Global coordinator instance
coordinator = None  # Will be instantiated in startup_event

# --- Pydantic Model for Telegram Update ---
class TelegramUpdate(BaseModel):
    update_id: int
    # Add other fields from Telegram Update object as needed
    # e.g., message: Optional[dict] = None
    #       edited_message: Optional[dict] = None
    #       ... etc
    # For now, just capture the raw data
    class Config:
        extra = 'allow' # Allow extra fields not explicitly defined

# Global variable for Coordinator
coordinator: Coordinator | None = None 

# --- Lifespan Context Manager ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup and shutdown operations."""
    global coordinator # Access the global coordinator

    logger.info("Application startup sequence initiated...")
    
    # Initialize Coordinator first (dependency for webhooks)
    logger.info("Initializing Coordinator...")
    
    # Create a new coordinator or use the existing one
    if coordinator is None:
        coordinator = Coordinator()
    
    await coordinator.initialize()
    logger.info("Coordinator initialized.")
    
    # Clean up old log files
    purge_old_logs() 
    
    # Register webhooks using the URL from the config object
    webhook_base_url = config.telegram.webhook_base_url # Use config value
    if webhook_base_url:
        logger.info(f"Registering webhooks with base URL: {webhook_base_url}")
        await coordinator.register_webhooks(webhook_base_url)
        logger.info("Webhooks registration process initiated.")
    else:
        logger.warning("WEBHOOK_BASE_URL not set in config/env. Skipping webhook registration.")

    logger.info("Bot-Command Monitor is ready to receive updates.")
    
    yield # Application runs here

    # --- Shutdown logic ---
    logger.info("Application shutdown sequence initiated...")
    if coordinator:
        logger.info("Shutting down Coordinator...")
        await coordinator.shutdown()
        logger.info("Coordinator shut down.")
    else:
        logger.info("Coordinator not initialized, skipping shutdown.")
    logger.info("Bot-Command shut down complete.")


# Initialize FastAPI app with the lifespan manager
app = FastAPI(lifespan=lifespan)

# --- Utility Functions ---

# Purge old log files
def purge_old_logs(log_dir="logs", max_days=30):
    """
    Delete log files older than max_days.
    
    Args:
        log_dir: Directory containing log files
        max_days: Maximum age of log files in days
    """
    try:
        if not os.path.exists(log_dir):
            return
            
        import time
        
        logger.info(f"Purging log files older than {max_days} days")
        
        # Get current time
        now = time.time()
        
        # Calculate cutoff time
        cutoff = now - (max_days * 86400)
        
        # List all files in log directory
        count = 0
        for file in os.listdir(log_dir):
            file_path = os.path.join(log_dir, file)
            
            # Skip if not a file
            if not os.path.isfile(file_path):
                continue
                
            # Skip if not a log file
            if not file.startswith("bot_command_") or not file.endswith(".log"):
                continue
                
            # Get file modification time
            mod_time = os.path.getmtime(file_path)
            
            # Delete if older than cutoff
            if mod_time < cutoff:
                try:
                    os.remove(file_path)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to delete old log file {file_path}: {str(e)}")
                    
        if count > 0:
            logger.info(f"Purged {count} old log files")
    except Exception as e:
        logger.error(f"Error purging old logs: {str(e)}")

# Handle shutdown signals (Replaced by FastAPI lifespan)
# def signal_handler():
#     if coordinator:
#         asyncio.create_task(coordinator.shutdown())

# Argument parsing (Removed, rely on env vars or FastAPI config)
# def parse_arguments():
#    ... (removed) ...

# --- FastAPI Endpoints ---
@app.get("/")
async def read_root():
    """Root endpoint for health check."""
    return {"message": "Bot-Command Monitor Active"}

@app.post("/{bot_username}")
async def handle_webhook(bot_username: str, update: TelegramUpdate, request: Request):
    """Receives webhook updates from Telegram for a specific bot username."""
    # Add check to ensure coordinator is initialized
    if coordinator is None:
        logger.error("Received webhook request before Coordinator was initialized.")
        raise HTTPException(status_code=503, detail="Service temporarily unavailable, please retry shortly.")
        
    # Optional: Verify source IP matches Telegram's ranges
    # client_host = request.client.host
    # if not is_telegram_ip(client_host): # Implement is_telegram_ip check
    #     logger.warning(f"Received webhook from untrusted IP: {client_host}")
    #     raise HTTPException(status_code=403, detail="Forbidden")

    logger.debug(f"Received webhook for username '{bot_username}': {list(update.dict().keys())}")

    # Look up the token for the given username
    token = await coordinator.get_token_for_username(bot_username)

    if not token:
        logger.warning(f"Webhook received for unknown or inactive bot username: {bot_username}")
        raise HTTPException(status_code=404, detail="Bot username not found or not monitored")

    # Pass the update and the resolved token to the coordinator
    try:
        # Convert Pydantic model back to dict for existing handler (if needed)
        # or adapt handler to accept the Pydantic model directly
        await coordinator.handle_webhook_update(token, update.dict()) 
    except Exception as e:
        logger.error(f"Error processing webhook update for bot {bot_username} (token {token[:4]}...): {e}", exc_info=True)
        # Return 500 to Telegram so it retries later
        raise HTTPException(status_code=500, detail="Internal Server Error")

    # Return 200 OK to Telegram to acknowledge receipt
    return {"status": "ok"}

# Old main async function (Replaced by FastAPI startup/shutdown events)
# async def main():
#    ... (removed) ...

# Log the effective log level before starting server
logger.info(f"Final check: Effective logging level set to: {logging.getLevelName(logging.getLogger().getEffectiveLevel())}")

if __name__ == "__main__":
    # Run the FastAPI application using uvicorn
    port = int(os.getenv("PORT", "8000"))
    logger.info(f"Starting web server on 0.0.0.0:{port} with HTTPS")
    
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=port, 
        reload=False, 
        log_config=None, 
        ssl_keyfile="config/ssl/privkey.pem", 
        ssl_certfile="config/ssl/fullchain.pem"
    )
