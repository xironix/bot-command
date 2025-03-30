"""
Base async client implementation for Bot-Command.

This module provides a base class for async clients with standardized
initialization, shutdown, and connection management patterns.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional, Dict

logger = logging.getLogger(__name__)

class BaseAsyncClient(ABC):
    """
    Base class for async clients with standardized lifecycle management.
    
    This abstract class provides a common pattern for client initialization,
    shutdown, and connection validation.
    """
    
    def __init__(self, name: str):
        """
        Initialize the base async client.
        
        Args:
            name: Client name for logging
        """
        self.name = name
        self.logger = logging.getLogger(f"{__name__}.{name}")
        self.initialized = False
        self._shutdown_event = asyncio.Event()
        
    @abstractmethod
    async def _initialize_client(self) -> bool:
        """
        Initialize the client connection.
        
        This method should be implemented by subclasses to handle the
        specific client initialization logic.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        pass
        
    @abstractmethod
    async def _shutdown_client(self) -> None:
        """
        Shutdown the client connection.
        
        This method should be implemented by subclasses to handle the
        specific client shutdown logic.
        """
        pass
        
    async def initialize(self) -> bool:
        """
        Initialize the client.
        
        This method handles the common initialization logic and delegates
        specific initialization to _initialize_client.
        
        Returns:
            True if initialization was successful, False otherwise
        """
        if self.initialized:
            self.logger.debug(f"{self.name} already initialized")
            return True
            
        self.logger.info(f"Initializing {self.name}")
        self._shutdown_event.clear()
        
        try:
            success = await self._initialize_client()
            
            if success:
                self.initialized = True
                self.logger.info(f"{self.name} initialized successfully")
                return True
            else:
                self.logger.error(f"Failed to initialize {self.name}")
                return False
        except Exception as e:
            self.logger.error(f"Error initializing {self.name}: {str(e)}", exc_info=True)
            return False
            
    async def close(self) -> None:
        """
        Close the client connection.
        
        This method handles the common shutdown logic and delegates
        specific shutdown to _shutdown_client.
        """
        if not self.initialized:
            self.logger.debug(f"{self.name} not initialized, nothing to close")
            return
            
        self.logger.info(f"Shutting down {self.name}")
        self._shutdown_event.set()
        
        try:
            await self._shutdown_client()
            self.initialized = False
            self.logger.info(f"{self.name} shut down successfully")
        except Exception as e:
            self.logger.error(f"Error shutting down {self.name}: {str(e)}", exc_info=True)
            
    async def ensure_initialized(self) -> bool:
        """
        Ensure the client is initialized.
        
        If the client is already initialized, this method returns True.
        Otherwise, it attempts to initialize the client.
        
        Returns:
            True if the client is initialized, False otherwise
        """
        if self.initialized:
            return True
            
        return await self.initialize()
        
    def is_shutdown_requested(self) -> bool:
        """
        Check if shutdown has been requested.
        
        Returns:
            True if shutdown has been requested, False otherwise
        """
        return self._shutdown_event.is_set()
        
    async def wait_for_shutdown(self, timeout: Optional[float] = None) -> bool:
        """
        Wait for shutdown event.
        
        Args:
            timeout: Optional timeout in seconds
            
        Returns:
            True if shutdown event was set, False if timeout occurred
        """
        try:
            await asyncio.wait_for(self._shutdown_event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False
            
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        Get client status information.
        
        This method should be implemented by subclasses to return
        status information about the client.
        
        Returns:
            Dictionary with status information
        """
        pass