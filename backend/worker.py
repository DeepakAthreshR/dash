import os
import redis
import logging
import sys
from rq import Worker, Queue, Connection
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - WORKER - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

listen = ['default']

# Connect to Redis
redis_url = os.getenv('REDIS_URL', 'redis://redis:6379')

try:
    conn = redis.from_url(redis_url)
    logger.info(f"✅ Worker connected to Redis at {redis_url}")
except Exception as e:
    logger.error(f"❌ Failed to connect to Redis: {e}")
    sys.exit(1)

if __name__ == '__main__':
    with Connection(conn):
        logger.info("👷 Worker started, listening for jobs...")
        worker = Worker(map(Queue, listen))
        worker.work()