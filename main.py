#!/usr/bin/env python3
"""
Bot-Command - Covert Intelligence-Gathering Tool for Telegram Stealer Bots

This tool silently intercepts and replicates the data collection process of 
Telegram-based stealer bots without modifying their behavior or alerting operators.
"""

import asyncio
import argparse
import logging
import os
import signal
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv

from src.coordinator import Coordinator

# Load environment variables
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

# Configure logging
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        file_handler
    ]
)

# Set specific log levels for noisy libraries
logging.getLogger("telethon").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("elasticsearch").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

# Global coordinator instance
coordinator = None

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
        from datetime import timedelta
        
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

# Handle shutdown signals
def signal_handler():
    if coordinator:
        asyncio.create_task(coordinator.shutdown())

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Bot-Command - Covert Intelligence-Gathering Tool")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode with detailed logging")
    parser.add_argument("--debug-dir", type=str, default="debug_logs", help="Directory for debug output (default: debug_logs)")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], 
                      help="Set logging level (default: INFO)")
    return parser.parse_args()

async def main():
    """Main entry point for the application."""
    global coordinator
    
    # Parse command line arguments
    args = parse_arguments()
    
    # Override log level from command line if specified
    if args.log_level:
        log_level_name = args.log_level.upper()
        log_level = getattr(logging, log_level_name, logging.INFO)
        logging.getLogger().setLevel(log_level)
        logger.info(f"Log level set to {log_level_name}")
    
    # Clean up old log files
    purge_old_logs()
    
    logger.info("Starting Bot-Command...")
    
    # Create and initialize the coordinator
    coordinator = Coordinator()
    
    # Enable debug mode if requested
    if args.debug:
        logger.info(f"Debug mode enabled, output will be saved to {args.debug_dir}")
        coordinator.enable_debug_mode(args.debug_dir)
    
    await coordinator.initialize()
    
    # Start monitoring bots
    # In a production environment, this would use bots from configuration
    # or a database of bots to monitor
    await coordinator.start_monitoring()
    
    # Register signal handlers for graceful shutdown
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        # Keep the main task running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    finally:
        # Clean up resources
        if coordinator:
            await coordinator.shutdown()
        logger.info("Bot-Command shut down")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}", exc_info=True)
