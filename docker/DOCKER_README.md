# Docker Setup for Bot-Command

This document describes how to set up the Docker environment for the Bot-Command application with SSL-enabled Elasticsearch and Kibana.

## Prerequisites

- Docker and Docker Compose installed
- SSL certificates (fullchain.pem and privkey.pem) available in the `config/ssl` directory
- Python 3.8+ with pip installed

## Setup Process

1. **Prepare SSL Certificates**

   Place your SSL certificates in the `config/ssl` directory:
   - `fullchain.pem` - Your certificate chain file
   - `privkey.pem` - Your private key file

   If you don't have certificates, you can generate self-signed ones for testing:
   ```bash
   mkdir -p config/ssl
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout config/ssl/privkey.pem -out config/ssl/fullchain.pem
   ```

2. **Run the Setup Script**

   ```bash
   ./setup_docker.py
   ```

   This script will:
   - Generate secure random passwords for MongoDB and Elasticsearch
   - Update the `.env` file with the correct credentials
   - Start the Docker containers
   - Set up the GeoIP pipeline in Elasticsearch
   - Import Kibana dashboards

3. **Verify the Setup**

   After the setup script completes, you should be able to access:
   - Elasticsearch at `https://localhost:9200` (user: elastic, password: in .env file)
   - Kibana at `https://localhost:5601` (same credentials as Elasticsearch)
   - MongoDB at `mongodb://localhost:27017` (user: admin, password: in .env file)

## Manual Container Management

If you need to manage the containers manually:

- **Start containers**: `docker-compose up -d`
- **Stop containers**: `docker-compose down`
- **View logs**: `docker-compose logs`
- **Restart a service**: `docker-compose restart <service_name>`

## Security Notes

1. The SSL certificates used for Elasticsearch and Kibana should be kept secure.
2. The `.env` file contains sensitive credentials - make sure it's not committed to version control.
3. For production use, consider using a proper certificate from a trusted CA instead of self-signed certificates.
4. Elasticsearch is configured to use SSL/TLS for both HTTP and transport protocols.
5. Kibana is configured to use SSL/TLS for the web interface.

## Troubleshooting

1. If Elasticsearch fails to start, check the logs:
   ```bash
   docker logs elasticsearch
   ```

2. If you see certificate-related errors, ensure your certificates are valid and in PEM format.

3. If Kibana can't connect to Elasticsearch, check if Elasticsearch is running and if the certificates are correctly set up.

4. If you need to reset the setup, you can run:
   ```bash
   docker-compose down -v
   ```
   This will remove all containers and volumes. Then run the setup script again.

5. To update the SSL certificates without losing data:
   ```bash
   # Place new certificates in config/ssl directory
   docker-compose restart elasticsearch kibana
   ```

## Data Management

- Data is persisted in Docker volumes for each service:
  - `elasticsearch-data`: Elasticsearch indices and data
  - `kibana-data`: Kibana settings and saved objects
  - `mongodb-data`: MongoDB databases and collections

- To back up data, you can use Docker volume backup commands or set up scheduled backups for each service.

## GeoIP Enrichment

The setup includes a GeoIP ingest pipeline for Elasticsearch, which enriches IP addresses with geolocation data. This enables:

1. Visualizing source locations on a map in Kibana
2. Filtering and aggregating by geographic regions
3. Enhanced correlation capabilities based on location proximity

## Kibana Dashboards

Predefined dashboards are imported during setup. These include:

1. **Overview Dashboard**: Summary of intercepted data, top domains, and activity trends
2. **Credential Analytics**: Detailed view of stolen credentials by domain and value
3. **System Information**: Analysis of compromised systems and their characteristics
4. **Parser Performance**: Metrics on parser efficiency and success rates

To access dashboards, navigate to:
```
https://localhost:5601/app/dashboards
```

## Updating the Docker Environment

To update to newer versions of Elasticsearch, Kibana, or MongoDB:

1. Edit the `docker-compose.yml` file to change the image versions
2. Run `docker-compose down` followed by `docker-compose up -d`
3. Run the setup script to recreate necessary indices and pipelines

Note that major version upgrades might require additional steps. Refer to the official documentation for each service.
