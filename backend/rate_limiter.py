"""
Rate limiting for API endpoints
Uses in-memory storage (can be upgraded to Redis for distributed systems)
"""
import time
from collections import defaultdict
from threading import Lock
from functools import wraps
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)

class RateLimiter:
    """Simple in-memory rate limiter"""
    
    def __init__(self):
        self.requests = defaultdict(list)
        self.lock = Lock()
        self.default_limits = {
            'deploy': {'max_requests': 10, 'window': 3600},  # 10 deploys per hour
            'api': {'max_requests': 100, 'window': 60},     # 100 requests per minute
            'upload': {'max_requests': 5, 'window': 3600},   # 5 uploads per hour
        }
    
    def is_allowed(self, key: str, limit_type: str = 'api'):
        """
        Check if request is allowed
        Returns: (is_allowed, remaining_requests)
        """
        with self.lock:
            now = time.time()
            limits = self.default_limits.get(limit_type, self.default_limits['api'])
            max_requests = limits['max_requests']
            window = limits['window']
            
            # Clean old requests
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if now - req_time < window
            ]
            
            # Check limit
            if len(self.requests[key]) >= max_requests:
                remaining = 0
                return False, remaining
            
            # Add current request
            self.requests[key].append(now)
            remaining = max_requests - len(self.requests[key])
            return True, remaining
    
    def get_remaining(self, key: str, limit_type: str = 'api') -> int:
        """Get remaining requests"""
        with self.lock:
            now = time.time()
            limits = self.default_limits.get(limit_type, self.default_limits['api'])
            window = limits['window']
            
            # Clean old requests
            self.requests[key] = [
                req_time for req_time in self.requests[key]
                if now - req_time < window
            ]
            
            return limits['max_requests'] - len(self.requests[key])

# Global rate limiter instance
rate_limiter = RateLimiter()

def rate_limit(limit_type: str = 'api'):
    """Decorator for rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get client identifier (IP address)
            client_ip = request.remote_addr or 'unknown'
            key = f"{limit_type}:{client_ip}"
            
            is_allowed, remaining = rate_limiter.is_allowed(key, limit_type)
            
            if not is_allowed:
                logger.warning(f"Rate limit exceeded for {client_ip} ({limit_type})")
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Please try again later.',
                    'limit_type': limit_type
                }), 429
            
            # Add rate limit headers
            response = f(*args, **kwargs)
            if isinstance(response, tuple):
                response_obj, status_code = response
            else:
                response_obj = response
                status_code = 200
            
            # Add headers if response is a Flask response
            if hasattr(response_obj, 'headers'):
                response_obj.headers['X-RateLimit-Remaining'] = str(remaining)
                response_obj.headers['X-RateLimit-Limit'] = str(
                    rate_limiter.default_limits.get(limit_type, {}).get('max_requests', 100)
                )
            
            # Return tuple with status code if original response was a tuple
            if isinstance(response, tuple):
                return response_obj, status_code
            return response_obj
        
        return decorated_function
    return decorator

