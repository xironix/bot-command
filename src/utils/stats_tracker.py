"""
Stats tracking utility for Bot-Command.

This module provides a thread-safe, async-compatible stats tracking utility
for maintaining operation statistics across the application.
"""

import asyncio
import logging
from typing import Dict, Any, Union, Optional

logger = logging.getLogger(__name__)

class StatsTracker:
    """
    Thread-safe, async-compatible stats tracking utility.
    
    This class provides methods for tracking various statistics with proper
    locking to ensure thread safety in async contexts.
    """
    
    def __init__(self, initial_stats: Optional[Dict[str, Any]] = None):
        """
        Initialize stats tracker with optional initial stats.
        
        Args:
            initial_stats: Optional dictionary of initial statistics
        """
        self.stats = initial_stats or {}
        self.lock = asyncio.Lock()
        
    async def increment(self, key: str, amount: int = 1) -> None:
        """
        Increment a stat counter in a thread-safe manner.
        
        Args:
            key: Key of the stat to increment
            amount: Amount to increment by (default: 1)
        """
        async with self.lock:
            if key not in self.stats:
                self.stats[key] = 0
            self.stats[key] += amount
            
    async def update_nested(self, parent_key: str, child_key: str, key: str, amount: int = 1) -> None:
        """
        Update a nested stat counter in a thread-safe manner.
        
        Args:
            parent_key: Top-level key in stats dictionary
            child_key: Second-level key in stats dictionary
            key: Key within the nested dictionary to update
            amount: Amount to increment by (default: 1)
        """
        async with self.lock:
            if parent_key not in self.stats:
                self.stats[parent_key] = {}
                
            if child_key not in self.stats[parent_key]:
                self.stats[parent_key][child_key] = {}
                
            if key not in self.stats[parent_key][child_key]:
                self.stats[parent_key][child_key][key] = 0
                
            self.stats[parent_key][child_key][key] += amount
            
    async def update_average(self, parent_key: str, child_key: str, avg_key: str, 
                            count_key: str, new_value: Union[int, float]) -> None:
        """
        Update a running average value in a thread-safe manner.
        
        Args:
            parent_key: Top-level key in stats dictionary
            child_key: Second-level key in stats dictionary
            avg_key: Key for the average value
            count_key: Key for the count used in average calculation
            new_value: New value to include in the average
        """
        async with self.lock:
            if parent_key not in self.stats:
                self.stats[parent_key] = {}
                
            if child_key not in self.stats[parent_key]:
                self.stats[parent_key][child_key] = {avg_key: 0.0, count_key: 0}
                
            parent = self.stats[parent_key][child_key]
            
            if avg_key not in parent:
                parent[avg_key] = 0.0
                
            if count_key not in parent:
                parent[count_key] = 0
                
            # Increment count first
            parent[count_key] += 1
            
            # Calculate new average
            parent[avg_key] = (
                (parent[avg_key] * (parent[count_key] - 1) + new_value) / 
                parent[count_key]
            )
            
    async def get(self, key: str, default: Any = None) -> Any:
        """
        Get a stat value in a thread-safe manner.
        
        Args:
            key: Key of the stat to get
            default: Default value if key doesn't exist
            
        Returns:
            Stat value or default
        """
        async with self.lock:
            return self.stats.get(key, default)
            
    async def get_all(self) -> Dict[str, Any]:
        """
        Get a copy of all stats in a thread-safe manner.
        
        Returns:
            Copy of all stats
        """
        async with self.lock:
            return dict(self.stats)
            
    async def reset(self, key: Optional[str] = None) -> None:
        """
        Reset stats in a thread-safe manner.
        
        Args:
            key: Optional key to reset. If None, reset all stats.
        """
        async with self.lock:
            if key is None:
                self.stats = {}
            elif key in self.stats:
                self.stats[key] = 0 if isinstance(self.stats[key], (int, float)) else {}
                
    async def update_dict(self, new_stats: Dict[str, Any]) -> None:
        """
        Update stats with a new dictionary in a thread-safe manner.
        
        Args:
            new_stats: Dictionary of new stats to merge
        """
        async with self.lock:
            for key, value in new_stats.items():
                if key in self.stats and isinstance(self.stats[key], dict) and isinstance(value, dict):
                    # Merge dictionaries
                    self.stats[key].update(value)
                else:
                    # Replace value
                    self.stats[key] = value
