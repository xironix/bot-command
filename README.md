# Bot-Command

A covert intelligence-gathering tool designed to silently intercept and replicate the data collection process of Telegram-based stealer bots.

## Overview

Bot-Command monitors Telegram-based stealer bots without modifying their behavior or alerting operators. It captures credentials, session cookies, autofill data, crypto wallets, and system fingerprints in real-time, providing security researchers and intelligence teams with valuable insights into active threats.

## Features

- **Silent Interception**: Monitors Telegram bots without detection
- **Optimized Architecture**: Uses worker pools for efficient processing
- **Structured Storage**: MongoDB for credentials, cookies, and more
- **Advanced Correlation**: Elasticsearch for pattern detection and analysis
- **Real-Time Analytics**: Visualize threat intelligence and bot activity

## Requirements

- Python 3.13+
- Docker and Docker Compose
- Telegram API credentials

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/bot-command.git
   cd bot-command
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Copy the example environment file and modify it:
   ```
   cp .env.example .env
   nano .env  # Edit with your credentials
   ```

   Required environment variables:
   ```
   # Telegram API credentials (required)
   TELEGRAM_API_ID=your_api_id_here
   TELEGRAM_API_HASH=your_api_hash_here
   
   # MongoDB credentials
   MONGODB_USERNAME=botcommand
   MONGODB_PASSWORD=your_secure_password
   
   # Optional configurations
   LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
   MEDIA_RETENTION_DAYS=30
   MAX_DISK_USAGE_GB=10
   ```

4. Set up the Docker environment:
   ```
   # Start MongoDB, Elasticsearch, and Kibana containers
   python setup_docker.py --all
   ```

## Usage

1. Ensure Docker services are running:
   ```
   docker-compose ps
   ```

2. Run the main application:
   ```
   python main.py
   ```

3. Access the dashboards:
   - Kibana: http://localhost:5601

## Configuration

Configuration settings can be modified in `config/settings.py` or via environment variables.

### Bot Filtering Options

You can control which Telegram bots to monitor with these options:

```
# In your .env file:

# Specific bots to monitor (comma-separated)
TELEGRAM_BOT_USERNAMES=stealerbot1,infobot2,datacollector3

# Bots to always ignore (comma-separated)
TELEGRAM_BOT_BLOCKLIST=goodbot1,legitimatebot2

# Monitor all bots encountered (true/false)
MONITOR_ALL_BOTS=false

# Use pattern matching to identify stealer bots (true/false)
FILTER_BY_PATTERNS=true
```

These settings let you control the scope of your monitoring, from targeting specific bots to monitoring all suspicious bots based on pattern matching.

### Media File Management

The application manages downloaded media files to prevent disk space exhaustion:

- Media files older than `MEDIA_RETENTION_DAYS` (default 30) are automatically deleted
- Maximum disk usage is controlled by `MAX_DISK_USAGE_GB` (default 10)
- When disk usage reaches the threshold, old files are cleaned up aggressively
- Downloaded files are tracked and properly cleaned up

## Security Considerations

Bot-Command operates as a passive intelligence collection tool and does not modify or interfere with the monitored bots. However, jurisdictional legalities should be considered before deployment.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
