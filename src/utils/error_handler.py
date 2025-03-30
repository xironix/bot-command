"""
Error handling utilities for Bot-Command.

This module provides standardized error handling utilities with retry logic,
consistent logging, and exception management.
"""

import asyncio
import functools
import logging
import time
from typing import Callable, Any, Optional, TypeVar, Union, Type, List, Dict, cast

logger = logging.getLogger(__name__)

# Type variables for better type hinting
T = TypeVar('T')
AsyncCallable = TypeVar('AsyncCallable', bound=Callable[..., Any])
SyncCallable = TypeVar('SyncCallable', bound=Callable[..., Any])

class RetryHandler:
    """
    Utility for handling retryable operations with backoff.
    
    This class provides decorators and methods for retrying operations
    with configurable backoff and error handling.
    """
    
    @staticmethod
    def async_retry(max_retries: int = 3, 
                   retry_delay: float = 1.0,
                   backoff_factor: float = 2.0,
                   exceptions: Union[Type[Exception], List[Type[Exception]]] = Exception,
                   log_level: int = logging.WARNING):
        """
        Decorator for retrying async functions with exponential backoff.
        
        Args:
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries in seconds
            backoff_factor: Factor to multiply delay by after each attempt
            exceptions: Exception type(s) to catch and retry
            log_level: Logging level for retry attempts
            
        Returns:
            Decorated async function with retry logic
        """
        def decorator(func: AsyncCallable) -> AsyncCallable:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                last_exception = None
                retry_exceptions = exceptions if isinstance(exceptions, tuple) else (exceptions,)
                
                for attempt in range(max_retries + 1):  # +1 for the initial attempt
                    try:
                        if attempt > 0:
                            delay = retry_delay * (backoff_factor ** (attempt - 1))
                            logger.log(log_level, 
                                      f"Retry {attempt}/{max_retries} for {func.__name__} "
                                      f"after {delay:.2f}s delay")
                            await asyncio.sleep(delay)
                            
                        return await func(*args, **kwargs)
                    except retry_exceptions as e:
                        last_exception = e
                        logger.log(log_level, 
                                  f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}: {str(e)}")
                        
                        # If this was the last attempt, re-raise
                        if attempt >= max_retries:
                            logger.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
                            raise last_exception
                    except Exception as e:
                        # Don't retry other exceptions
                        logger.error(f"Non-retryable error in {func.__name__}: {str(e)}")
                        raise
                        
                # This line should never be reached, but to satisfy mypy:
                assert last_exception is not None
                raise last_exception
                
            return cast(AsyncCallable, wrapper)
        return decorator
        
    @staticmethod
    def sync_retry(max_retries: int = 3, 
                  retry_delay: float = 1.0,
                  backoff_factor: float = 2.0,
                  exceptions: Union[Type[Exception], List[Type[Exception]]] = Exception,
                  log_level: int = logging.WARNING):
        """
        Decorator for retrying synchronous functions with exponential backoff.
        
        Args:
            max_retries: Maximum number of retry attempts
            retry_delay: Initial delay between retries in seconds
            backoff_factor: Factor to multiply delay by after each attempt
            exceptions: Exception type(s) to catch and retry
            log_level: Logging level for retry attempts
            
        Returns:
            Decorated function with retry logic
        """
        def decorator(func: SyncCallable) -> SyncCallable:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                last_exception = None
                retry_exceptions = exceptions if isinstance(exceptions, tuple) else (exceptions,)
                
                for attempt in range(max_retries + 1):  # +1 for the initial attempt
                    try:
                        if attempt > 0:
                            delay = retry_delay * (backoff_factor ** (attempt - 1))
                            logger.log(log_level, 
                                      f"Retry {attempt}/{max_retries} for {func.__name__} "
                                      f"after {delay:.2f}s delay")
                            time.sleep(delay)
                            
                        return func(*args, **kwargs)
                    except retry_exceptions as e:
                        last_exception = e
                        logger.log(log_level, 
                                  f"Attempt {attempt + 1}/{max_retries + 1} failed for {func.__name__}: {str(e)}")
                        
                        # If this was the last attempt, re-raise
                        if attempt >= max_retries:
                            logger.error(f"All {max_retries + 1} attempts failed for {func.__name__}")
                            raise last_exception
                    except Exception as e:
                        # Don't retry other exceptions
                        logger.error(f"Non-retryable error in {func.__name__}: {str(e)}")
                        raise
                        
                # This line should never be reached, but to satisfy mypy:
                assert last_exception is not None
                raise last_exception
                
            return cast(SyncCallable, wrapper)
        return decorator


class ErrorLogger:
    """
    Utility for standardized error logging.
    
    This class provides decorators for consistent error logging
    across the application.
    """
    
    @staticmethod
    def log_async_errors(func: AsyncCallable) -> AsyncCallable:
        """
        Decorator for logging errors in async functions.
        
        Args:
            func: Async function to decorate
            
        Returns:
            Decorated async function with error logging
        """
        @functools.wraps(func)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                func_logger = logging.getLogger(func.__module__)
                func_logger.error(
                    f"Error in {func.__name__}: {str(e)}", 
                    exc_info=True
                )
                raise
                
        return cast(AsyncCallable, wrapper)
        
    @staticmethod
    def log_sync_errors(func: SyncCallable) -> SyncCallable:
        """
        Decorator for logging errors in synchronous functions.
        
        Args:
            func: Function to decorate
            
        Returns:
            Decorated function with error logging
        """
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                func_logger = logging.getLogger(func.__module__)
                func_logger.error(
                    f"Error in {func.__name__}: {str(e)}", 
                    exc_info=True
                )
                raise
                
        return cast(SyncCallable, wrapper)
        
    @staticmethod
    def async_safe_operation(default_value: Any = None, 
                            log_level: int = logging.ERROR,
                            log_traceback: bool = True):
        """
        Decorator for making async operations safe by catching exceptions.
        
        Args:
            default_value: Value to return if operation fails
            log_level: Logging level for errors
            log_traceback: Whether to include traceback in log
            
        Returns:
            Decorated async function that never raises exceptions
        """
        def decorator(func: AsyncCallable) -> AsyncCallable:
            @functools.wraps(func)
            async def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return await func(*args, **kwargs)
                except Exception as e:
                    func_logger = logging.getLogger(func.__module__)
                    func_logger.log(
                        log_level,
                        f"Operation {func.__name__} failed: {str(e)}",
                        exc_info=log_traceback
                    )
                    return default_value
                    
            return cast(AsyncCallable, wrapper)
        return decorator
        
    @staticmethod
    def sync_safe_operation(default_value: Any = None,
                           log_level: int = logging.ERROR,
                           log_traceback: bool = True):
        """
        Decorator for making synchronous operations safe by catching exceptions.
        
        Args:
            default_value: Value to return if operation fails
            log_level: Logging level for errors
            log_traceback: Whether to include traceback in log
            
        Returns:
            Decorated function that never raises exceptions
        """
        def decorator(func: SyncCallable) -> SyncCallable:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    func_logger = logging.getLogger(func.__module__)
                    func_logger.log(
                        log_level,
                        f"Operation {func.__name__} failed: {str(e)}",
                        exc_info=log_traceback
                    )
                    return default_value
                    
            return cast(SyncCallable, wrapper)
        return decorator
