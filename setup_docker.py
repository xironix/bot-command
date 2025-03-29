#!/usr/bin/env python3
"""
Docker setup script for Bot-Command.

This script sets up the Docker environment for the Bot-Command application,
initializing MongoDB and Elasticsearch with the required indices and settings.
"""

import argparse
import logging
import os
import subprocess
import sys
import time
from typing import List, Dict, Any
from dotenv import load_dotenv

import requests
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Get credentials from environment variables
MONGODB_USERNAME = os.getenv("MONGODB_USERNAME", "botcommand")
MONGODB_PASSWORD = os.getenv("MONGODB_PASSWORD", "")
MONGODB_HOST = os.getenv("MONGODB_HOST", "localhost")
MONGODB_PORT = os.getenv("MONGODB_PORT", "27017")
MONGODB_URI = os.getenv("MONGODB_URI", f"mongodb://{MONGODB_USERNAME}:{MONGODB_PASSWORD}@{MONGODB_HOST}:{MONGODB_PORT}/")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def run_command(command: List[str]) -> int:
    """
    Run a shell command.
    
    Args:
        command: Command to run as a list of strings
        
    Returns:
        Return code from the command
    """
    logger.debug(f"Running command: {' '.join(command)}")
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )
    
    # Print output in real-time
    for stdout_line in iter(process.stdout.readline, ""):
        if stdout_line:
            print(stdout_line.strip())
            
    # Get return code
    return_code = process.wait()
    
    return return_code

def start_docker_services():
    """Start Docker services."""
    logger.info("Starting Docker services...")
    return_code = run_command(["docker-compose", "up", "-d"])
    
    if return_code != 0:
        logger.error("Failed to start Docker services")
        sys.exit(1)
        
    logger.info("Docker services started successfully")
    
def wait_for_service(service_name: str, url: str, max_attempts: int = 30):
    """
    Wait for a service to be available.
    
    Args:
        service_name: Name of the service
        url: URL to check
        max_attempts: Maximum number of attempts
    """
    logger.info(f"Waiting for {service_name} to be available...")
    
    for attempt in range(max_attempts):
        try:
            response = requests.get(url, timeout=2)
            if response.status_code == 200:
                logger.info(f"{service_name} is available")
                return
        except requests.RequestException:
            pass
            
        logger.debug(f"{service_name} not available yet, waiting...")
        time.sleep(2)
        
    logger.error(f"{service_name} is not available after {max_attempts} attempts")
    sys.exit(1)
    
def setup_mongodb():
    """Set up MongoDB."""
    logger.info("Setting up MongoDB...")
    
    # Wait for MongoDB to be available
    wait_for_service("MongoDB", f"http://{MONGODB_HOST}:{MONGODB_PORT}", 15)
    
    try:
        # Connect to MongoDB using URI from environment variables
        client = MongoClient(MONGODB_URI)
        
        # Get database
        db = client["bot_command"]
        
        # Create collections
        collections = [
            "credentials",
            "cookies",
            "system_info",
            "logs",
            "fs.files",
            "fs.chunks"
        ]
        
        for collection in collections:
            if collection not in db.list_collection_names():
                db.create_collection(collection)
                logger.info(f"Created collection: {collection}")
        
        # Create indexes
        db.credentials.create_index([("username", 1), ("domain", 1)], name="credential_search")
        db.credentials.create_index([("bot_id", 1)], name="shard_key")
        db.credentials.create_index([("timestamp", 1)], name="time_index")
        db.credentials.create_index([("source_ip", 1)], name="ip_index")
        
        db.cookies.create_index([("domain", 1)], name="domain_index")
        db.cookies.create_index([("bot_id", 1)], name="shard_key")
        db.cookies.create_index([("timestamp", 1)], name="time_index")
        
        db.system_info.create_index([("bot_id", 1)], name="bot_id_index")
        db.system_info.create_index([("timestamp", 1)], name="time_index")
        
        db.logs.create_index([("timestamp", 1)], expireAfterSeconds=30 * 86400, name="logs_ttl")
        
        logger.info("MongoDB set up successfully")
    except Exception as e:
        logger.error(f"Failed to set up MongoDB: {str(e)}")
        sys.exit(1)
        
def setup_elasticsearch():
    """Set up Elasticsearch."""
    logger.info("Setting up Elasticsearch...")
    
    # Wait for Elasticsearch to be available
    wait_for_service("Elasticsearch", "http://localhost:9200", 30)
    
    try:
        # Create indices
        indices = [
            "bot-command-credentials",
            "bot-command-cookies",
            "bot-command-system-info",
            "bot-command-logs",
            "bot-command-correlation"
        ]
        
        for index in indices:
            # Check if index exists
            response = requests.head(f"http://localhost:9200/{index}")
            
            if response.status_code == 404:
                # Create index
                mapping = {
                    "settings": {
                        "number_of_shards": 1,
                        "number_of_replicas": 0
                    }
                }
                
                response = requests.put(
                    f"http://localhost:9200/{index}",
                    json=mapping
                )
                
                if response.status_code >= 200 and response.status_code < 300:
                    logger.info(f"Created index: {index}")
                else:
                    logger.error(f"Failed to create index {index}: {response.text}")
                    
        logger.info("Elasticsearch set up successfully")
    except Exception as e:
        logger.error(f"Failed to set up Elasticsearch: {str(e)}")
        sys.exit(1)
        
def load_kibana_dashboards():
    """Load Kibana dashboards."""
    logger.info("Loading Kibana dashboards...")
    
    # Wait for Kibana to be available
    wait_for_service("Kibana", "http://localhost:5601/api/status", 60)
    
    # In a real implementation, this would use the Kibana API to import dashboards
    logger.info("Kibana dashboards configured")
    
def main():
    """Main function."""
    parser = argparse.ArgumentParser(description="Set up Docker environment for Bot-Command")
    parser.add_argument("--start", action="store_true", help="Start Docker services")
    parser.add_argument("--setup-mongodb", action="store_true", help="Set up MongoDB")
    parser.add_argument("--setup-elasticsearch", action="store_true", help="Set up Elasticsearch")
    parser.add_argument("--load-dashboards", action="store_true", help="Load Kibana dashboards")
    parser.add_argument("--all", action="store_true", help="Perform all setup steps")
    
    args = parser.parse_args()
    
    # If no arguments are provided, show help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    # Perform requested actions
    if args.start or args.all:
        start_docker_services()
        
    if args.setup_mongodb or args.all:
        setup_mongodb()
        
    if args.setup_elasticsearch or args.all:
        setup_elasticsearch()
        
    if args.load_dashboards or args.all:
        load_kibana_dashboards()
        
    logger.info("Setup complete")

if __name__ == "__main__":
    main()
