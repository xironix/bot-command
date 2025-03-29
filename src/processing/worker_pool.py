"""
Worker pool implementation for Bot-Command.

This module handles the worker pool architecture for processing bot messages,
downloading media, and writing to the database.
"""

import asyncio
import logging
import queue
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Coroutine

from config.settings import config

logger = logging.getLogger(__name__)

class WorkerPool:
    """
    Worker pool for processing tasks asynchronously.
    
    This class implements a worker pool architecture with separate queues for
    different types of tasks (monitoring, downloads, database writes).
    """
    
    def __init__(self):
        """Initialize worker pools and queues."""
        self.config = config.worker_pools
        
        # Task queues
        self.monitor_queue = asyncio.Queue()
        self.download_queue = queue.Queue()
        self.database_queue = queue.Queue()
        
        # Thread pools
        self.download_executor = ThreadPoolExecutor(
            max_workers=self.config.download_workers,
            thread_name_prefix="download_worker"
        )
        self.database_executor = ThreadPoolExecutor(
            max_workers=self.config.database_workers,
            thread_name_prefix="db_worker"
        )
        
        # Track tasks and workers
        self.tasks = []
        self.running = False
        
    async def start(self):
        """Start worker pools and processing tasks."""
        logger.info("Starting worker pools")
        self.running = True
        
        # Start monitor workers
        for i in range(self.config.monitor_workers):
            task = asyncio.create_task(self._monitor_worker(i))
            self.tasks.append(task)
            
        # Start download workers
        for i in range(self.config.download_workers):
            threading.Thread(
                target=self._download_worker,
                args=(i,),
                daemon=True,
                name=f"download_worker_{i}"
            ).start()
            
        # Start database workers
        for i in range(self.config.database_workers):
            threading.Thread(
                target=self._database_worker,
                args=(i,),
                daemon=True,
                name=f"db_worker_{i}"
            ).start()
            
        logger.info("All worker pools started")
        
    async def stop(self):
        """Stop all worker pools."""
        logger.info("Stopping worker pools")
        self.running = False
        
        # Cancel async tasks
        for task in self.tasks:
            task.cancel()
            
        # Shutdown thread pools
        self.download_executor.shutdown(wait=False)
        self.database_executor.shutdown(wait=False)
        
        logger.info("Worker pools stopped")
        
    async def submit_monitor_task(self, task_func: Callable[..., Coroutine], *args, **kwargs):
        """
        Submit a task to the monitor queue.
        
        Args:
            task_func: Async function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
        """
        await self.monitor_queue.put((task_func, args, kwargs))
        
    def submit_download_task(self, task_func: Callable, *args, **kwargs):
        """
        Submit a task to the download queue.
        
        Args:
            task_func: Function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
        """
        self.download_queue.put((task_func, args, kwargs))
        
    def submit_database_task(self, task_func: Callable, *args, **kwargs):
        """
        Submit a task to the database queue.
        
        Args:
            task_func: Function to execute
            *args: Arguments for the function
            **kwargs: Keyword arguments for the function
        """
        self.database_queue.put((task_func, args, kwargs))
        
    async def _monitor_worker(self, worker_id: int):
        """
        Worker for processing monitoring tasks.
        
        Args:
            worker_id: Worker identifier
        """
        logger.info(f"Monitor worker {worker_id} started")
        
        try:
            while self.running:
                try:
                    # Get task from queue with timeout
                    task_func, args, kwargs = await asyncio.wait_for(
                        self.monitor_queue.get(),
                        timeout=1.0
                    )
                    
                    # Execute task
                    try:
                        await task_func(*args, **kwargs)
                    except Exception as e:
                        logger.error(f"Error in monitor task: {str(e)}", exc_info=True)
                    finally:
                        self.monitor_queue.task_done()
                except asyncio.TimeoutError:
                    # No tasks in queue, continue
                    pass
                except asyncio.CancelledError:
                    # Worker cancelled
                    break
        except Exception as e:
            logger.error(f"Monitor worker {worker_id} error: {str(e)}", exc_info=True)
        finally:
            logger.info(f"Monitor worker {worker_id} stopped")
            
    def _download_worker(self, worker_id: int):
        """
        Worker for processing download tasks.
        
        Args:
            worker_id: Worker identifier
        """
        logger.info(f"Download worker {worker_id} started")
        
        try:
            while self.running:
                try:
                    # Get task from queue with timeout
                    task_func, args, kwargs = self.download_queue.get(timeout=1.0)
                    
                    # Execute task
                    try:
                        task_func(*args, **kwargs)
                    except Exception as e:
                        logger.error(f"Error in download task: {str(e)}", exc_info=True)
                    finally:
                        self.download_queue.task_done()
                except queue.Empty:
                    # No tasks in queue, continue
                    pass
        except Exception as e:
            logger.error(f"Download worker {worker_id} error: {str(e)}", exc_info=True)
        finally:
            logger.info(f"Download worker {worker_id} stopped")
            
    def _database_worker(self, worker_id: int):
        """
        Worker for processing database tasks.
        
        Args:
            worker_id: Worker identifier
        """
        logger.info(f"Database worker {worker_id} started")
        
        try:
            while self.running:
                try:
                    # Get task from queue with timeout
                    task_func, args, kwargs = self.database_queue.get(timeout=1.0)
                    
                    # Execute task
                    try:
                        task_func(*args, **kwargs)
                    except Exception as e:
                        logger.error(f"Error in database task: {str(e)}", exc_info=True)
                    finally:
                        self.database_queue.task_done()
                except queue.Empty:
                    # No tasks in queue, continue
                    pass
        except Exception as e:
            logger.error(f"Database worker {worker_id} error: {str(e)}", exc_info=True)
        finally:
            logger.info(f"Database worker {worker_id} stopped")
