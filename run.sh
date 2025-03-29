#!/bin/bash
# Helper script to run Bot-Command with Docker services

# Check if Docker services are running
MONGO_STATUS=$(docker ps -q -f name=bot-command-mongodb)
ELASTIC_STATUS=$(docker ps -q -f name=bot-command-elasticsearch)
KIBANA_STATUS=$(docker ps -q -f name=bot-command-kibana)

# If any service is not running, start Docker services
if [[ -z "$MONGO_STATUS" || -z "$ELASTIC_STATUS" || -z "$KIBANA_STATUS" ]]; then
    echo "Some Docker services are not running. Starting all services..."
    python setup_docker.py --all
    
    # Wait a bit for services to initialize
    echo "Waiting for services to initialize..."
    sleep 5
fi

# Run the main application
echo "Starting Bot-Command..."
python main.py
