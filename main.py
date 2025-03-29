#!/usr/bin/env python3
"""
Bot-Command - Covert Intelligence-Gathering Tool for Telegram Stealer Bots

This tool silently intercepts and replicates the data collection process of 
Telegram-based stealer bots without modifying their behavior or alerting operators.
"""

# Standard library imports first
import asyncio
import argparse
import logging
import os
import signal
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler

# Third-party imports
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import uvicorn

# Local application/library specific imports
from src.coordinator import Coordinator
from src.config import load_env_vars
from src.database.init_db import init_database

# Load environment variables AFTER imports but BEFORE using them
load_dotenv()

# Create logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Get log level from environment
log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
log_level = getattr(logging, log_level_name, logging.INFO)

# Configure rotating file handler
log_file = f"logs/bot_command_{datetime.now().strftime('%Y%m%d')}.log"
file_handler = RotatingFileHandler(
    log_file,
    maxBytes=10 * 1024 * 1024,  # 10 MB
    backupCount=10,
    encoding="utf-8"
)

# Set formatter for the file handler (optional but good practice)
file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(file_formatter)

# Configure basic logging (without handlers initially)
# Remove format, as RichHandler handles console format
# Remove handlers, as we'll add them manually
logging.basicConfig(
    level=log_level,
    handlers=[] # Start with no handlers here
)

# Create RichHandler for console output
rich_handler = RichHandler(
    level=log_level, # Set level for this handler
    show_time=True,
    show_level=True,
    show_path=False, # Don't show path by default, can be noisy
    markup=True, # Enable Rich markup in log messages
    rich_tracebacks=True # Enable rich tracebacks
)

# Add handlers to the root logger
root_logger = logging.getLogger()
root_logger.addHandler(rich_handler) # Add colorful console handler
root_logger.addHandler(file_handler) # Add rotating file handler

# Set specific log levels for noisy libraries
logging.getLogger("telethon").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Global coordinator instance
coordinator = None

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

# --- Global coordinator and FastAPI app ---
coordinator = Coordinator() # Instantiate coordinator globally
app = FastAPI(title="Bot-Command Monitor", version="0.1.0")

# Load environment variables (consider doing this earlier if needed by logging)
# env_vars = load_env_vars() # Might need adjustment based on FastAPI startup

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

# --- FastAPI Lifespan Events ---
@app.on_event("startup")
async def startup_event():
    """Handles application startup: initialize coordinator and set webhooks."""
    logger.info("Application startup...")
    
    # Clean up old log files
    purge_old_logs() # Keep log purging
    
    logger.info("Initializing Coordinator...")
    await coordinator.initialize()
    
    # Register webhooks for active bots using the provided URL
    webhook_base_url = "https://webhook.xenoops.net"
    logger.info(f"Registering webhooks with base URL: {webhook_base_url}")
    await coordinator.register_webhooks(webhook_base_url)
    
    # The old start_monitoring() call is removed as webhooks replace polling.
    # logger.info("Registering webhooks (placeholder)...") 
    # Example: await coordinator.register_webhooks("https://webhook.xenoops.net/webhook") 
    
    logger.info("Coordinator initialized and webhooks set.")
    logger.info("Bot-Command Monitor is ready to receive updates.")

@app.on_event("shutdown")
async def shutdown_event():
    """Handles application shutdown: cleanup coordinator resources."""
    logger.info("Application shutdown...")
    if coordinator:
        logger.info("Shutting down Coordinator...")
        await coordinator.shutdown()
    logger.info("Bot-Command shut down complete.")

# --- FastAPI Endpoints ---
@app.get("/")
async def read_root():
    """Root endpoint for health check."""
    return {"message": "Bot-Command Monitor Active"}

@app.post("/webhook/{token}")
async def handle_webhook(token: str, update: TelegramUpdate, request: Request):
    """Receives webhook updates from Telegram for a specific bot token."""
    # Optional: Verify source IP matches Telegram's ranges
    # client_host = request.client.host
    # if not is_telegram_ip(client_host): # Implement is_telegram_ip check
    #     logger.warning(f"Received webhook from untrusted IP: {client_host}")
    #     raise HTTPException(status_code=403, detail="Forbidden")

    logger.debug(f"Received webhook for token {token[:4]}...: {update.dict()}")
    
    # Pass the update to the coordinator for processing
    try:
        # Convert Pydantic model back to dict for existing handler (if needed)
        # or adapt handler to accept the Pydantic model directly
        await coordinator.handle_webhook_update(token, update.dict()) 
        # ^^^ NOTE: handle_webhook_update method needs to be created in Coordinator
    except Exception as e:
        logger.error(f"Error processing webhook update for token {token[:4]}...: {e}", exc_info=True)
        # Return 500 to Telegram so it retries later
        raise HTTPException(status_code=500, detail="Internal Server Error")

    # Return 200 OK to Telegram to acknowledge receipt
    return {"status": "ok"}

# Old main async function (Replaced by FastAPI startup/shutdown events)
# async def main():
#    ... (removed) ...

if __name__ == "__main__":
    # Configure log level based on environment variable (similar to before)
    log_level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    initial_log_level = getattr(logging, log_level_name, logging.INFO)
    logging.getLogger().setLevel(initial_log_level)
    logger.info(f"Log level set to {log_level_name}")

    # Run the FastAPI application using uvicorn
    # Get port from environment variable or default to 8000
    port = int(os.getenv("PORT", "8000"))
    logger.info(f"Starting web server on 0.0.0.0:{port}")
    
    # Note: For production, disable reload=True
    # Note: Ensure this port is reachable by Telegram (e.g., via reverse proxy to 443)
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=False) # Changed reload to False
