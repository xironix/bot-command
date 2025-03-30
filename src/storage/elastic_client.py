"""
Elasticsearch client for log correlation and data analysis.

This module handles the connection to Elasticsearch and provides methods for
storing, retrieving, and analyzing intercepted data.
"""

import logging
import os  # Import os module
from datetime import datetime, timedelta
from typing import Dict, List, Any
from urllib.parse import urlparse # Added import
import ssl # Import ssl module
import socket # Added import

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from config.settings import config

logger = logging.getLogger(__name__)

class ElasticsearchManager:
    """Manages Elasticsearch connections and operations."""
    
    def __init__(self):
        """Initialize Elasticsearch manager."""
        self.config = config.elasticsearch
        
        # --- Read auth from config --- 
        auth_params = {}
        
        # Check for username and password in config
        if self.config.username and self.config.password:
            logger.info(f"Found Elasticsearch credentials in config: username={self.config.username}")
            auth_params['basic_auth'] = (self.config.username, self.config.password)
            logger.info("Using Elasticsearch Basic authentication from config.")
        else:
            logger.warning("No Elasticsearch authentication credentials found in config. This will likely fail with 401 Unauthorized.")
            
        # Parse URI to determine if HTTPS
        self.main_uri = self.config.uri
        self.is_https = self.main_uri.startswith("https://")
        logger.info(f"Elasticsearch URI scheme: {'HTTPS' if self.is_https else 'HTTP'}")
            
        # --- Configure SSL explicitly --- 
        verify_certs_value = self.config.verify_certs
        ca_certs_path = None
        
        # Log connection info
        logger.info(f"Connecting to Elasticsearch endpoint: {self.config.uri}")
        
        # Use SSL Certificate Authority if provided in env and verification is enabled
        if verify_certs_value:
            ca_certs_env = os.getenv("ELASTICSEARCH_CA_CERTS")
            if ca_certs_env:
                if os.path.exists(ca_certs_env):
                    ca_certs_path = ca_certs_env
                    logger.info(f"Using CA certificate for verification: {ca_certs_path}")
                else:
                    logger.warning(f"CA certificate not found at: {ca_certs_env}")
        else:
            logger.info("Skipping CA certificate check as verification is disabled.")
        
        # --- Initialize Client with Conditional Arguments --- 

        # Store URI
        self.main_uri = self.config.uri
        self.is_https = self.main_uri.startswith("https://")
        
        # Always force disable certificate verification for development
        verify_certs_setting = False
        
        # Configure SSL context manually
        ssl_context = None
        if self.is_https:
            import ssl
            # Create a custom SSL context that doesn't verify certificates
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            # Some environments need this for older/self-signed certificates
            ssl_context.options |= ssl.OP_LEGACY_SERVER_CONNECT
            
            # Additional options to make it more permissive
            # Disable certificate verification entirely
            ssl_context.verify_flags = ssl.VERIFY_DEFAULT
            # Set minimum TLS version to be more permissive
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1
        
        # Main client args
        self.es_args = {
            "hosts": [self.main_uri],
            "verify_certs": verify_certs_setting,
            "ssl_show_warn": False,  # Don't show SSL warnings when we've disabled verification
            "timeout": 30,  # Set a reasonable timeout
            "retry_on_timeout": True  # Retry when connection timeouts occur
        }
        
        # Add SSL context if needed
        if ssl_context and self.is_https:
            self.es_args["ssl_context"] = ssl_context
        
        # Add basic auth if configured
        if self.config.username and self.config.password:
            self.es_args["basic_auth"] = (self.config.username, self.config.password)

        # Log the *actual* verification setting being used
        logger.info(f"Certificate verification for ES client set to: {self.es_args['verify_certs']}")
        logger.info(f"Using custom SSL context: {ssl_context is not None}")
        
        # Try connecting with a timeout to avoid hanging
        try:
            self.client = AsyncElasticsearch(**self.es_args)
        except Exception as e:
            logger.error(f"Error initializing Elasticsearch client: {e}", exc_info=True)
            self.client = None
            
        # Index names
        self.credentials_index = f"{self.config.index_prefix}-credentials"
        self.cookies_index = f"{self.config.index_prefix}-cookies"
        self.system_info_index = f"{self.config.index_prefix}-system-info"
        self.logs_index = f"{self.config.index_prefix}-logs"
        self.correlation_index = f"{self.config.index_prefix}-correlation"
        self.stats_index = f"{self.config.index_prefix}-parser-stats"
        
    async def initialize(self):
        """Initialize Elasticsearch indices and templates."""
        # Check if Elasticsearch is available
        try:
            logger.info("Attempting to connect to Elasticsearch...")
            
            # Add more detailed debug about connection settings
            logger.info(f"Connection settings: URI={self.main_uri}, verify_certs={self.config.verify_certs}")
            
            # Skip if client initialization failed
            if not self.client:
                logger.warning("Elasticsearch client was not initialized properly")
                return False
                
            # Try to ping with verbose debugging
            try:
                # Add detailed network debugging - socket level
                uri_parts = urlparse(self.main_uri)
                hostname = uri_parts.hostname
                port = uri_parts.port or (443 if uri_parts.scheme == 'https' else 80)
                
                # Try a simple socket connection to see if the host is reachable
                logger.info(f"Testing basic socket connection to {hostname}:{port}")
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect((hostname, port))
                    s.close()
                    logger.info(f"Socket connection to {hostname}:{port} successful")
                except Exception as socket_err:
                    logger.error(f"Socket connection to {hostname}:{port} failed: {socket_err}")
                    
                    # Try alternative port 9200 directly if default HTTPS port failed
                    try:
                        alt_port = 9200
                        logger.info(f"Trying alternative port: {hostname}:{alt_port}")
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(5)
                        s.connect((hostname, alt_port))
                        s.close()
                        logger.info(f"Socket connection to {hostname}:{alt_port} successful")
                    except Exception as alt_socket_err:
                        logger.error(f"Alternative socket connection also failed: {alt_socket_err}")
                
                # Try manually accessing via HTTP to test if HTTPS is the issue
                # logger.info("Checking if HTTP is available instead of HTTPS...")
                # try:
                #     import requests
                #     http_url = self.main_uri.replace("https://", "http://")
                #     logger.info(f"Trying HTTP URL: {http_url}")
                #     requests.get(http_url, timeout=5, verify=False)
                #     logger.info("HTTP connection successful - consider changing to HTTP in .env")
                # except Exception as http_err:
                #     logger.warning(f"HTTP attempt also failed: {http_err}")
                
                # Now try the actual ping
                logger.info("Attempting Elasticsearch ping...")
                ping_result = await self.client.ping()
                if ping_result:
                    logger.info("Elasticsearch is available - ping succeeded")
                    await self._create_indices()
                    return True
                else:
                    logger.warning("Elasticsearch is not available - ping failed")
                    return False
            except Exception as e:
                logger.error(f"Error pinging Elasticsearch: {e}")
                logger.error(f"Error type: {type(e).__name__}")
                return False
                
        except Exception as e:
            # Log more details about the connection error
            logger.error(f"Failed to initialize Elasticsearch: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            
            # Check the URL components to help with troubleshooting
            try:
                parsed_url = urlparse(self.main_uri)
                logger.error(f"Elasticsearch connection details - Host: {parsed_url.hostname}, Port: {parsed_url.port}, "
                          f"Protocol: {parsed_url.scheme}")
            except Exception as parse_error:
                logger.error(f"Error parsing Elasticsearch URI: {str(parse_error)}")
                
            logger.error("Please check your Elasticsearch server status, network connectivity, and authentication settings")
            return False
            
    async def _create_indices(self):
        """Create Elasticsearch indices with appropriate mappings."""
        # Check if client is available
        if not self.client:
            logger.warning("Cannot create indices - Elasticsearch client is not available")
            return
            
        # Credentials index
        credentials_mapping = {
            "mappings": {
                "properties": {
                    "username": {"type": "keyword"},
                    "password": {"type": "keyword"},
                    "domain": {"type": "keyword"},
                    "bot_id": {"type": "keyword"},
                    "bot_username": {"type": "keyword"},
                    "message_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            }
        }
        
        await self._create_index_if_not_exists(self.credentials_index, credentials_mapping)
        
        # Cookies index
        cookies_mapping = {
            "mappings": {
                "properties": {
                    "domain": {"type": "keyword"},
                    "value": {"type": "text"},
                    "bot_id": {"type": "keyword"},
                    "bot_username": {"type": "keyword"},
                    "message_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "source_ip": {"type": "ip"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            }
        }
        
        await self._create_index_if_not_exists(self.cookies_index, cookies_mapping)
        
        # System info index
        system_info_mapping = {
            "mappings": {
                "properties": {
                    "os": {"type": "text"},
                    "hardware": {"type": "text"},
                    "ip": {"type": "ip"},
                    "full_info": {"type": "text"},
                    "bot_id": {"type": "keyword"},
                    "bot_username": {"type": "keyword"},
                    "message_id": {"type": "keyword"},
                    "timestamp": {"type": "date"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            }
        }
        
        await self._create_index_if_not_exists(self.system_info_index, system_info_mapping)
        
        # Logs index
        logs_mapping = {
            "mappings": {
                "properties": {
                    "bot_id": {"type": "keyword"},
                    "bot_username": {"type": "keyword"},
                    "message_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "event_type": {"type": "keyword"},
                    "details": {"type": "text"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            }
        }
        
        await self._create_index_if_not_exists(self.logs_index, logs_mapping)
        
        # Correlation index
        correlation_mapping = {
            "mappings": {
                "properties": {
                    "bot_id": {"type": "keyword"},
                    "user_id": {"type": "keyword"},
                    "ip_address": {"type": "ip"},
                    "domains": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "correlation_type": {"type": "keyword"},
                    "confidence": {"type": "float"},
                    "details": {"type": "object"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            }
        }
        
        await self._create_index_if_not_exists(self.correlation_index, correlation_mapping)
        
        # Parser stats index
        stats_mapping = {
            "mappings": {
                "properties": {
                    "type": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "total_processed": {"type": "integer"},
                    "successful_credential_extractions": {"type": "integer"},
                    "successful_cookie_extractions": {"type": "integer"},
                    "successful_crypto_wallet_extractions": {"type": "integer"},
                    "high_value_extractions": {"type": "integer"},
                    "plugin_successes": {"type": "integer"},
                    "plugin_failures": {"type": "integer"},
                    "overall_success_rate": {"type": "float"},
                    "plugin_data": {"type": "object"}
                }
            },
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 1
            }
        }
        
        await self._create_index_if_not_exists(self.stats_index, stats_mapping)
        
    async def _create_index_if_not_exists(self, index_name: str, mapping: Dict[str, Any]):
        """
        Create an Elasticsearch index if it doesn't exist.
        
        Args:
            index_name: Name of the index
            mapping: Index mapping and settings
        """
        # Check if client is available
        if not self.client:
            logger.warning(f"Cannot create index {index_name} - Elasticsearch client is not available")
            return
            
        try:
            # Check if index exists
            if not await self.client.indices.exists(index=index_name):
                # Create index
                await self.client.indices.create(index=index_name, body=mapping)
                logger.info(f"Created Elasticsearch index {index_name}")
            else:
                logger.debug(f"Elasticsearch index {index_name} already exists")
        except Exception as e:
            logger.error(f"Failed to create Elasticsearch index {index_name}: {str(e)}")
            
    async def index_credential(self, credential_data: Dict[str, Any]) -> str:
        """
        Index a credential in Elasticsearch.
        
        Args:
            credential_data: Credential data
            
        Returns:
            ID of the indexed document
        """
        if not self.client:
            logger.warning("Cannot index credential - Elasticsearch client is not available")
            return "elasticsearch_not_available"
            
        try:
            # Ensure timestamp field
            if "timestamp" not in credential_data:
                credential_data["timestamp"] = datetime.utcnow()
                
            # Index document
            result = await self.client.index(
                index=self.credentials_index,
                document=credential_data
            )
            
            return result["_id"]
        except Exception as e:
            logger.error(f"Failed to index credential: {str(e)}")
            return f"error_{str(e)}"
            
    async def index_cookie(self, cookie_data: Dict[str, Any]) -> str:
        """
        Index a cookie in Elasticsearch.
        
        Args:
            cookie_data: Cookie data
            
        Returns:
            ID of the indexed document
        """
        if not self.client:
            logger.warning("Cannot index cookie - Elasticsearch client is not available")
            return "elasticsearch_not_available"
            
        try:
            # Ensure timestamp field
            if "timestamp" not in cookie_data:
                cookie_data["timestamp"] = datetime.utcnow()
                
            # Index document
            result = await self.client.index(
                index=self.cookies_index,
                document=cookie_data
            )
            
            return result["_id"]
        except Exception as e:
            logger.error(f"Failed to index cookie: {str(e)}")
            return f"error_{str(e)}"
            
    async def index_system_info(self, system_data: Dict[str, Any]) -> str:
        """
        Index system information in Elasticsearch.
        
        Args:
            system_data: System data
            
        Returns:
            ID of the indexed document
        """
        if not self.client:
            logger.warning("Cannot index system info - Elasticsearch client is not available")
            return "elasticsearch_not_available"
            
        try:
            # Ensure timestamp field
            if "timestamp" not in system_data:
                system_data["timestamp"] = datetime.utcnow()
                
            # Index document
            result = await self.client.index(
                index=self.system_info_index,
                document=system_data
            )
            
            return result["_id"]
        except Exception as e:
            logger.error(f"Failed to index system info: {str(e)}")
            return f"error_{str(e)}"
            
    async def log_activity(self, log_data: Dict[str, Any]) -> str:
        """
        Log bot activity in Elasticsearch.
        
        Args:
            log_data: Log data
            
        Returns:
            ID of the indexed document
        """
        if not self.client:
            logger.warning("Cannot log activity - Elasticsearch client is not available")
            return "elasticsearch_not_available"
            
        try:
            # Ensure timestamp field
            if "timestamp" not in log_data:
                log_data["timestamp"] = datetime.utcnow()
                
            # Index document
            result = await self.client.index(
                index=self.logs_index,
                document=log_data
            )
            
            return result["_id"]
        except Exception as e:
            logger.error(f"Failed to log activity: {str(e)}")
            return f"error_{str(e)}"
            
    async def create_correlation(self, correlation_data: Dict[str, Any]) -> str:
        """
        Create a correlation in Elasticsearch.
        
        Args:
            correlation_data: Correlation data
            
        Returns:
            ID of the indexed document
        """
        if not self.client:
            logger.warning("Cannot create correlation - Elasticsearch client is not available")
            return "elasticsearch_not_available"
            
        try:
            # Ensure timestamp field
            if "timestamp" not in correlation_data:
                correlation_data["timestamp"] = datetime.utcnow()
                
            # Index document
            result = await self.client.index(
                index=self.correlation_index,
                document=correlation_data
            )
            
            return result["_id"]
        except Exception as e:
            logger.error(f"Failed to create correlation: {str(e)}")
            return f"error_{str(e)}"
            
    async def search_credentials(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        """
        Search for credentials in Elasticsearch.
        
        Args:
            query: Elasticsearch query
            size: Maximum number of results
            
        Returns:
            List of matching credentials
        """
        if not self.client:
            logger.warning("Cannot search credentials - Elasticsearch client is not available")
            return []
            
        try:
            result = await self.client.search(
                index=self.credentials_index,
                body={"query": query},
                size=size
            )
            
            return [hit["_source"] for hit in result["hits"]["hits"]]
        except Exception as e:
            logger.error(f"Failed to search credentials: {str(e)}")
            return []
            
    async def correlate_data(self, bot_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """
        Correlate data from different indices.
        
        Args:
            bot_id: Bot ID
            hours: Number of hours to look back
            
        Returns:
            List of correlation results
        """
        if not self.client:
            logger.warning("Cannot correlate data - Elasticsearch client is not available")
            return []
            
        try:
            start_time = datetime.utcnow() - timedelta(hours=hours)
            
            # Find all system info records for this bot
            system_info_query = {
                "bool": {
                    "must": [
                        {"term": {"bot_id": bot_id}},
                        {"range": {"timestamp": {"gte": start_time.isoformat()}}}
                    ]
                }
            }
            
            system_info_result = await self.client.search(
                index=self.system_info_index,
                body={"query": system_info_query},
                size=100
            )
            
            system_info_records = [hit["_source"] for hit in system_info_result["hits"]["hits"]]
            
            # Find all credentials for this bot
            credentials_query = {
                "bool": {
                    "must": [
                        {"term": {"bot_id": bot_id}},
                        {"range": {"timestamp": {"gte": start_time.isoformat()}}}
                    ]
                }
            }
            
            credentials_result = await self.client.search(
                index=self.credentials_index,
                body={"query": credentials_query},
                size=100
            )
            
            credential_records = [hit["_source"] for hit in credentials_result["hits"]["hits"]]
            
            # Build correlations
            correlations = []
            
            # Group credentials by domain
            domain_credentials = {}
            for credential in credential_records:
                domain = credential.get("domain")
                if domain:
                    if domain not in domain_credentials:
                        domain_credentials[domain] = []
                    domain_credentials[domain].append(credential)
                    
            # Create domain-based correlations
            for domain, credentials in domain_credentials.items():
                if len(credentials) > 1:
                    # Multiple credentials for the same domain
                    correlation = {
                        "bot_id": bot_id,
                        "correlation_type": "multiple_credentials_same_domain",
                        "timestamp": datetime.utcnow(),
                        "domains": [domain],
                        "confidence": 0.8,
                        "details": {
                            "credential_count": len(credentials),
                            "credential_ids": [cred.get("_id", "unknown") for cred in credentials]
                        }
                    }
                    correlations.append(correlation)
                    
            # Correlate system info with credentials
            for system_info in system_info_records:
                ip = system_info.get("ip")
                if ip:
                    correlation = {
                        "bot_id": bot_id,
                        "correlation_type": "system_info_with_credentials",
                        "timestamp": datetime.utcnow(),
                        "ip_address": ip,
                        "domains": list(domain_credentials.keys()),
                        "confidence": 0.9,
                        "details": {
                            "system_info_id": system_info.get("_id", "unknown"),
                            "credential_count": sum(len(creds) for creds in domain_credentials.values()),
                            "os": system_info.get("os")
                        }
                    }
                    correlations.append(correlation)
                    
            # Save correlations
            if correlations and self.client:
                # Bulk index correlations
                bulk_operations = []
                for correlation in correlations:
                    bulk_operations.append({
                        "_index": self.correlation_index,
                        "_source": correlation
                    })
                    
                try:
                    await async_bulk(self.client, bulk_operations)
                except Exception as bulk_error:
                    logger.error(f"Failed to bulk index correlations: {bulk_error}")
                
            return correlations
        except Exception as e:
            logger.error(f"Failed to correlate data: {str(e)}")
            return []
            
    async def index_parser_stats(self, stats_data: Dict[str, Any]) -> str:
        """
        Index parser statistics in Elasticsearch.
        
        Args:
            stats_data: Parser statistics data
            
        Returns:
            ID of the indexed document
        """
        if not self.client:
            logger.warning("Cannot index parser stats - Elasticsearch client is not available")
            return "elasticsearch_not_available"
            
        try:
            # Create document with flattened structure for better querying
            stats_doc = {
                "type": "parser_stats",
                "timestamp": datetime.utcnow(),
                "total_processed": stats_data.get("total_processed", 0),
                "successful_credential_extractions": stats_data.get("successful_credential_extractions", 0),
                "successful_cookie_extractions": stats_data.get("successful_cookie_extractions", 0),
                "successful_crypto_wallet_extractions": stats_data.get("successful_crypto_wallet_extractions", 0),
                "high_value_extractions": stats_data.get("high_value_extractions", 0),
                "plugin_successes": stats_data.get("plugin_successes", 0),
                "plugin_failures": stats_data.get("plugin_failures", 0),
                "overall_success_rate": stats_data.get("overall_success_rate", 0),
                "plugin_data": stats_data.get("plugins", {})
            }
            
            # Index document
            result = await self.client.index(
                index=self.stats_index,
                document=stats_doc
            )
            
            return result["_id"]
        except Exception as e:
            logger.error(f"Failed to index parser stats: {str(e)}")
            return f"error_{str(e)}"
            
    async def get_parser_stats_trends(self, days: int = 7) -> Dict[str, Any]:
        """
        Get parser statistics trends over time.
        
        Args:
            days: Number of days to look back
            
        Returns:
            Dictionary with trend data
        """
        if not self.client:
            logger.warning("Cannot get parser stats trends - Elasticsearch client is not available")
            return {"daily_trends": [], "top_plugins": []}
            
        try:
            start_time = datetime.utcnow() - timedelta(days=days)
            
            # Aggregation to get daily stats
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"type": "parser_stats"}},
                            {"range": {"timestamp": {"gte": start_time.isoformat()}}}
                        ]
                    }
                },
                "aggs": {
                    "stats_per_day": {
                        "date_histogram": {
                            "field": "timestamp",
                            "calendar_interval": "day"
                        },
                        "aggs": {
                            "total_processed": {"avg": {"field": "total_processed"}},
                            "success_rate": {"avg": {"field": "overall_success_rate"}},
                            "high_value": {"avg": {"field": "high_value_extractions"}},
                            "plugin_successes": {"avg": {"field": "plugin_successes"}}
                        }
                    },
                    "top_plugins": {
                        "terms": {
                            "field": "plugin_data.*.success_rate",
                            "size": 5,
                            "order": {"_key": "desc"}
                        }
                    }
                },
                "size": 0
            }
            
            result = await self.client.search(
                index=self.stats_index,
                body=query
            )
            
            return {
                "daily_trends": result.get("aggregations", {}).get("stats_per_day", {}).get("buckets", []),
                "top_plugins": result.get("aggregations", {}).get("top_plugins", {}).get("buckets", [])
            }
        except Exception as e:
            logger.error(f"Failed to get parser stats trends: {str(e)}")
            return {"daily_trends": [], "top_plugins": []}
            
    async def close(self):
        """Close Elasticsearch connection."""
        if self.client:
            await self.client.close()
        else:
            logger.debug("No Elasticsearch client to close")
