import logging
import redis
import json
import os
from docker_manager import DockerManager
from db_manager import DatabaseManager

logger = logging.getLogger(__name__)

# Initialize managers
redis_url = os.getenv('REDIS_URL', 'redis://redis:6379')
r = redis.from_url(redis_url)
docker_manager = DockerManager()
db_manager = DatabaseManager()

def emit_log_redis(dep_id, message, type='log'):
    """Push log message to a Redis list for the frontend to consume"""
    log_entry = json.dumps({'type': type, 'message': message})
    r.rpush(f"logs:{dep_id}", log_entry)
    r.expire(f"logs:{dep_id}", 3600)
    logger.info(f"[{dep_id}] {message}")

def run_deployment_task(dep_id, project_dir, deployment_type, config):
    """
    Background task to handle the deployment process.
    Executed by the RQ Worker.
    """
    try:
        emit_log_redis(dep_id, f"🚀 Worker picked up job for {dep_id}", 'info')
        
        container_id = None
        port = None

        # Execute deployment based on type
        if deployment_type == 'static':
            container_id, port = docker_manager.deploy_static_site(
                project_dir, dep_id, config, 
                log_callback=lambda msg: emit_log_redis(dep_id, msg)
            )
        else:
            container_id, port = docker_manager.deploy_web_service(
                project_dir, dep_id, config, 
                log_callback=lambda msg: emit_log_redis(dep_id, msg)
            )

        # Update Database with success state
        dep = db_manager.get_deployment(dep_id)
        if dep:
            dep['status'] = 'active'
            dep['containerId'] = container_id
            dep['port'] = port
            dep['directUrl'] = f"http://localhost:{port}"
            db_manager.save_deployment(dep)

        emit_log_redis(dep_id, f"✅ Deployment successful on port {port}", 'success')
        
        # --- FIX START ---
        # Send the DONE signal directly without wrapping it in a 'message' string
        success_payload = {
            'type': 'done',       # Top-level type
            'success': True,      # Top-level success flag
            'deployment': {
                'id': dep_id,
                'containerId': container_id,
                'port': port,
                'directUrl': f"http://localhost:{port}",
                'status': 'active'
            }
        }
        # Push raw JSON directly
        r.rpush(f"logs:{dep_id}", json.dumps(success_payload))
        # --- FIX END ---

    except Exception as e:
        error_msg = str(e)
        logger.error(f"Job failed for {dep_id}: {error_msg}")
        emit_log_redis(dep_id, f"❌ Deployment failed: {error_msg}", 'error')
        
        # --- FIX START ---
        # Send failure signal directly
        failure_payload = {
            'type': 'done',
            'success': False,
            'error': error_msg
        }
        r.rpush(f"logs:{dep_id}", json.dumps(failure_payload))
        # --- FIX END ---
        
        # Update DB status to failed
        try:
            dep = db_manager.get_deployment(dep_id)
            if dep:
                dep['status'] = 'failed'
                db_manager.save_deployment(dep)
        except:
            pass