"""
Test the CircuitBreaker implementation.
"""

import unittest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import time

from src.processing.worker_pool import CircuitBreaker

class TestCircuitBreaker(unittest.TestCase):
    """Tests for the CircuitBreaker class."""
    
    def setUp(self):
        """Set up test environment."""
        self.breaker = CircuitBreaker("test_service", failure_threshold=3, recovery_timeout=2)
        
    def test_initial_state(self):
        """Test initial state of the circuit breaker."""
        self.assertEqual(self.breaker.name, "test_service")
        self.assertEqual(self.breaker.failure_threshold, 3)
        self.assertEqual(self.breaker.recovery_timeout, 2)
        self.assertEqual(self.breaker.state, "CLOSED")
        self.assertTrue(self.breaker.is_closed())
        
    def test_record_failure(self):
        """Test recording failures."""
        # First failure
        self.breaker.record_failure()
        self.assertEqual(self.breaker.failure_count, 1)
        self.assertEqual(self.breaker.state, "CLOSED")
        self.assertTrue(self.breaker.is_closed())
        
        # Second failure
        self.breaker.record_failure()
        self.assertEqual(self.breaker.failure_count, 2)
        self.assertEqual(self.breaker.state, "CLOSED")
        self.assertTrue(self.breaker.is_closed())
        
        # Third failure should open the circuit
        self.breaker.record_failure()
        self.assertEqual(self.breaker.failure_count, 3)
        self.assertEqual(self.breaker.state, "OPEN")
        self.assertFalse(self.breaker.is_closed())
        
    def test_recovery_timeout(self):
        """Test recovery timeout behavior."""
        # Open the circuit
        for _ in range(3):
            self.breaker.record_failure()
            
        self.assertEqual(self.breaker.state, "OPEN")
        self.assertFalse(self.breaker.is_closed())
        
        # Backdate the last failure time to simulate timeout
        self.breaker.last_failure_time = datetime.now() - timedelta(seconds=3)
        
        # Circuit should be HALF_OPEN now
        self.assertTrue(self.breaker.is_closed())
        self.assertEqual(self.breaker.state, "HALF_OPEN")
        
    def test_record_success(self):
        """Test recording a success after failure."""
        # Open the circuit
        for _ in range(3):
            self.breaker.record_failure()
            
        # Transition to HALF_OPEN
        self.breaker.state = "HALF_OPEN"
        
        # Record a success
        self.breaker.record_success()
        self.assertEqual(self.breaker.state, "CLOSED")
        self.assertEqual(self.breaker.failure_count, 0)
        self.assertTrue(self.breaker.is_closed())
        
    def test_full_cycle(self):
        """Test a full circuit breaker cycle."""
        # Initially closed
        self.assertTrue(self.breaker.is_closed())
        
        # Failures open the circuit
        for _ in range(3):
            self.breaker.record_failure()
        
        # Circuit now open
        self.assertFalse(self.breaker.is_closed())
        
        # Wait for timeout
        self.breaker.last_failure_time = datetime.now() - timedelta(seconds=3)
        
        # Circuit should allow one test request
        self.assertTrue(self.breaker.is_closed())
        self.assertEqual(self.breaker.state, "HALF_OPEN")
        
        # Successful request closes the circuit
        self.breaker.record_success()
        self.assertTrue(self.breaker.is_closed())
        self.assertEqual(self.breaker.state, "CLOSED")
        
if __name__ == "__main__":
    unittest.main()
