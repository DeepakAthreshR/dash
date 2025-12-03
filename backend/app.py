from flask import Flask, request, jsonify, Response, stream_with_context, session
from flask_cors import CORS
from github import Github, GithubException
import tempfile
import os
import uuid
import socket
import requests
import shutil
from datetime import datetime
from docker_manager import DockerManager
from github_handler import GitHubHandler
from auto_detector import ProjectDetector
from werkzeug.utils import secure_filename
import zipfile
import json
import traceback
import logging
import time
import sys
import werkzeug.exceptions
from dotenv import load_dotenv
from db_manager import DatabaseManager
from rate_limiter import rate_limit

# RQ / Redis imports
from redis import Redis
from rq import Queue
from tasks import run_deployment_task

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('deployment.log')
    ]
)

logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change_this_secret_key_in_production')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7  # 7 days
cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')
CORS(app, supports_credentials=True, origins=cors_origins)

# Initialize Redis Queue
redis_url = os.getenv('REDIS_URL', 'redis://redis:6379')
try:
    redis_conn = Redis.from_url(redis_url)
    q = Queue(connection=redis_conn)
    logger.info(f"✅ Connected to Redis Queue at {redis_url}")
except Exception as e:
    logger.error(f"❌ Failed to connect to Redis: {str(e)}")

app.config['MAX_CONTENT_LENGTH'] = 600 * 1024 * 1024  # 600MB
app.config['JSON_SORT_KEYS'] = False

# Initialize managers
try:
    docker_manager = DockerManager()
    github_handler = GitHubHandler()
    db_manager = DatabaseManager()
    logger.info("✅ Managers initialized")
except Exception as e:
    logger.error(f"❌ Initialization failed: {str(e)}")
    sys.exit(1)

# Directory setup
UPLOAD_FOLDER = 'uploads'
PROJECTS_FOLDER = 'projects'
for dir_path in ['./deployments', './uploads', './projects', './persistent_storage', './volumes', './db']:
    os.makedirs(dir_path, exist_ok=True)
    try:
        os.chmod(dir_path, 0o777)
    except:
        pass

ALLOWED_EXTENSIONS = {'zip'}
MAX_FILE_SIZE = 600 * 1024 * 1024

###############################################
# Authentication & User Endpoints
###############################################

@app.route('/api/login/github', methods=['POST'])
def github_login():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({'error': 'Token required'}), 400
    try:
        g = Github(token)
        user = g.get_user()
        _ = user.login  # test token
        session['github_token'] = token
        session['github_user'] = user.login
        session.permanent = True
        logger.info(f"✅ GitHub login successful: {user.login}")
        return jsonify({'message': 'Login successful', 'username': user.login})
    except GithubException as e:
        logger.error(f"❌ GitHub login failed: {str(e)}")
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/logout/github', methods=['POST'])
def github_logout():
    session.pop('github_token', None)
    session.pop('github_user', None)
    logger.info("✅ GitHub logout successful")
    return jsonify({'message': 'Logged out'})

@app.route('/api/user/repos', methods=['GET'])
def list_repos():
    token = session.get('github_token')
    if not token:
        return jsonify({'error': 'Not authenticated'}), 401
    try:
        g = Github(token)
        user = g.get_user()
        repos = []
        for repo in user.get_repos():
            try:
                default_branch = repo.default_branch or 'main'
            except:
                default_branch = 'main'
            repos.append({
                'name': repo.full_name,
                'clone_url': repo.clone_url,
                'private': repo.private,
                'default_branch': default_branch
            })
        return jsonify({'repositories': repos})
    except GithubException as e:
        logger.error(f"❌ Failed to fetch repositories: {str(e)}")
        return jsonify({'error': 'Failed to fetch repositories'}), 500

@app.route('/api/check-github-session', methods=['GET'])
def check_github_session():
    token = session.get('github_token')
    username = session.get('github_user')
    if token and username:
        try:
            g = Github(token)
            user = g.get_user()
            return jsonify({'authenticated': True, 'username': user.login})
        except:
            session.pop('github_token', None)
            session.pop('github_user', None)
            return jsonify({'authenticated': False})
    return jsonify({'authenticated': False})

###############################################
# Helper Functions
###############################################

def save_deployment_version(deployment):
    dep_id = deployment['id']
    existing_versions = db_manager.get_deployment_versions(dep_id)
    next_version = len(existing_versions) + 1
    
    version = {
        'version': next_version,
        'containerId': deployment['containerId'],
        'timestamp': deployment['timestamp'],
        'config': deployment.get('config', {}),
        'status': 'previous'
    }
    
    db_manager.save_deployment_version(dep_id, version)
    
    if len(existing_versions) >= 10:
        oldest_version = existing_versions[-1]
        try:
            if oldest_version['containerId']:
                docker_manager.stop_container(oldest_version['containerId'])
        except:
            pass

def save_metrics(dep_id, stats):
    db_manager.save_metrics(dep_id, stats)

###############################################
# Health & Detection Endpoints
###############################################

@app.route('/api/health', methods=['GET'])
def health():
    try:
        docker_manager.client.ping()
        docker_healthy = True
    except:
        docker_healthy = False
    
    try:
        redis_conn.ping()
        redis_healthy = True
    except:
        redis_healthy = False
    
    status = 'healthy' if docker_healthy and redis_healthy else 'unhealthy'
    
    return jsonify({
        'status': status,
        'docker': 'connected' if docker_healthy else 'disconnected',
        'redis': 'connected' if redis_healthy else 'disconnected',
        'database': db_manager.db_type,
        'timestamp': datetime.now().isoformat(),
        'queue_length': len(q) if redis_healthy else 0
    }), 200 if status == 'healthy' else 503

@app.route('/api/detect-project', methods=['POST'])
def detect_project_endpoint():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if not file.filename.endswith('.zip'):
            return jsonify({'error': 'Only .zip files supported'}), 400
        
        temp_id = str(uuid.uuid4())[:8]
        temp_dir = f"./uploads/temp-{temp_id}"
        os.makedirs(temp_dir, exist_ok=True)
        
        try:
            filename = secure_filename(file.filename)
            file_path = os.path.join(temp_dir, filename)
            file.save(file_path)
            
            extract_dir = f"{temp_dir}/extracted"
            os.makedirs(extract_dir, exist_ok=True)
            
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_dir)
            
            extracted_files = os.listdir(extract_dir)
            if len(extracted_files) == 1 and os.path.isdir(os.path.join(extract_dir, extracted_files[0])):
                extract_dir = os.path.join(extract_dir, extracted_files[0])
            
            detector = ProjectDetector(extract_dir)
            detection_result = detector.detect_all()
            suggestions = detector.get_smart_suggestions()
            
            return jsonify({
                'success': True,
                'detection': detection_result,
                'suggestions': suggestions,
                'message': f"✅ Detected {suggestions['detected']}"
            }), 200
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    except Exception as e:
        logger.error(f"Detection error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detect-github', methods=['POST'])
def detect_github_project():
    try:
        data = request.json
        if not data.get('githubRepo'):
            return jsonify({'error': 'GitHub repository URL required'}), 400
        
        temp_id = str(uuid.uuid4())[:8]
        temp_dir = f"./uploads/temp-{temp_id}"
        
        try:
            token = session.get('github_token')
            github_handler.clone_repo(data['githubRepo'], temp_dir, data.get('branch', 'main'), token=token)
            
            detector = ProjectDetector(temp_dir)
            detection_result = detector.detect_all()
            suggestions = detector.get_smart_suggestions()
            
            return jsonify({
                'success': True,
                'detection': detection_result,
                'suggestions': suggestions,
                'message': f"✅ Detected {suggestions['detected']}"
            }), 200
        finally:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
    except Exception as e:
        logger.error(f"Detection error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

###############################################
# Deployment Endpoints (Queue Based)
###############################################

# --- NEW ENDPOINT FOR LOG STREAMING ---
@app.route('/api/deployments/<deployment_id>/stream', methods=['GET'])
def stream_logs_endpoint(deployment_id):
    """Stream logs for a specific deployment ID from Redis"""
    def generate():
        last_idx = 0
        empty_reads = 0
        
        yield f"data: {json.dumps({'type': 'info', 'message': f'📡 Attached to log stream for {deployment_id}'})}\n\n"
        
        while True:
            # Read logs from Redis (non-blocking)
            logs = redis_conn.lrange(f"logs:{deployment_id}", last_idx, -1)
            
            if logs:
                empty_reads = 0
                for log_raw in logs:
                    last_idx += 1
                    if isinstance(log_raw, bytes):
                        log_raw = log_raw.decode('utf-8')
                    
                    try:
                        # Forward log to client
                        yield f"data: {log_raw}\n\n"
                        
                        # Check if job is done
                        log_json = json.loads(log_raw)
                        if log_json.get('type') == 'done':
                            return
                    except:
                        # Just send raw if json parse fails
                        yield f"data: {log_raw}\n\n"
            else:
                empty_reads += 1
                # Check if we should stop listening (e.g. key expired or job finished long ago)
                # For now, timeout after 20 minutes of silence
                if empty_reads > 2400: 
                    yield f"data: {json.dumps({'type': 'error', 'message': 'Timeout waiting for logs'})}\n\n"
                    return
                time.sleep(0.5)

    return Response(stream_with_context(generate()), mimetype='text/event-stream')
# --------------------------------------

@app.route('/api/deploy-stream', methods=['POST'])
@rate_limit(limit_type='deploy')
def deploy_stream():
    """Deploy from GitHub with streaming logs via Redis Queue"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.json
        if not data or not data.get('projectName') or not data.get('githubRepo'):
            return jsonify({'error': 'Project name and repository required'}), 400
    except Exception as e:
        return jsonify({'error': f'Invalid request: {str(e)}'}), 400
    
    dep_id = str(uuid.uuid4())[:8]
    
    def generate():
        proj_dir = f"./deployments/{dep_id}"
        
        yield f"data: {json.dumps({'type': 'info', 'message': f'🚀 Queuing deployment {dep_id}'})}\n\n"
        
        try:
            branch = data.get('branch', 'main')
            token = session.get('github_token')
            
            yield f"data: {json.dumps({'type': 'info', 'message': f'📥 Cloning repository...'})}\n\n"
            
            try:
                github_handler.clone_repo(data['githubRepo'], proj_dir, branch, token=token)
            except Exception as clone_error:
                shutil.rmtree(proj_dir, ignore_errors=True)
                error_msg = str(clone_error)
                if 'authentication' in error_msg.lower():
                    error_msg = "❌ Authentication failed. Check your GitHub token."
                yield f"data: {json.dumps({'type': 'error', 'message': error_msg})}\n\n"
                yield f"data: {json.dumps({'type': 'done', 'success': False, 'error': error_msg})}\n\n"
                return

            deployment_type = data['deploymentType']
            config = data.get('config', {})
            config['environmentVariables'] = data.get('environmentVariables', [])
            config['persistentStorage'] = data.get('persistentStorage', False)
            config['healthCheckPath'] = data.get('healthCheckPath', '/')
            config['autoRestart'] = data.get('autoRestart', True)
            
            if config.get('persistentStorage'):
                config['volumeName'] = f"persistent_data_{dep_id}"

            deployment_record = {
                'id': dep_id,
                'projectName': data['projectName'],
                'deploymentType': deployment_type,
                'status': 'building',
                'url': f"/deploy/{dep_id}/",
                'directUrl': None,
                'timestamp': datetime.now().isoformat(),
                'containerId': None,
                'port': None,
                'source': 'github',
                'repo': data['githubRepo'],
                'branch': branch,
                'config': config,
                'environmentVariables': config['environmentVariables'],
                'version': 1,
                'healthCheckPath': config['healthCheckPath'],
                'autoRestart': config['autoRestart'],
                'volumePath': config.get('volumeName'),
                'customDomain': None
            }
            db_manager.save_deployment(deployment_record)
            save_deployment_version(deployment_record)

            try:
                job = q.enqueue(
                    run_deployment_task,
                    args=(dep_id, proj_dir, deployment_type, config),
                    job_timeout='15m',
                    result_ttl=86400
                )
                queue_pos = len(q)
                yield f"data: {json.dumps({'type': 'info', 'message': f'✅ Job queued. Position: {queue_pos}'})}\n\n"
            except Exception as q_error:
                yield f"data: {json.dumps({'type': 'error', 'message': f'Failed to queue: {str(q_error)}'})}\n\n"
                return

            # Reuse the stream logic by redirecting internally conceptually
            # But we duplicate the loop here for simplicity in this generator
            last_idx = 0
            empty_reads = 0
            
            while True:
                logs = redis_conn.lrange(f"logs:{dep_id}", last_idx, -1)
                
                if logs:
                    empty_reads = 0
                    for log_raw in logs:
                        last_idx += 1
                        if isinstance(log_raw, bytes):
                            log_raw = log_raw.decode('utf-8')
                        
                        try:
                            yield f"data: {log_raw}\n\n"
                            log_json = json.loads(log_raw)
                            if log_json.get('type') == 'done':
                                return
                        except:
                            pass
                else:
                    empty_reads += 1
                    if empty_reads > 2400:
                        yield f"data: {json.dumps({'type': 'error', 'message': 'Timeout waiting for logs'})}\n\n"
                        return
                    time.sleep(0.5)

        except Exception as e:
            logger.error(f"Deploy stream error: {str(e)}")
            yield f"data: {json.dumps({'type': 'error', 'message': f'Server Error: {str(e)}'})}\n\n"

    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/deploy-local', methods=['POST'])
@rate_limit(limit_type='upload')
def deploy_local():
    """Deploy from ZIP using Job Queue"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        project_name = request.form.get('projectName')
        deployment_type = request.form.get('deploymentType')
        
        config = json.loads(request.form.get('config', '{}'))
        config['environmentVariables'] = json.loads(request.form.get('environmentVariables', '[]'))
        config['persistentStorage'] = request.form.get('persistentStorage', 'false').lower() == 'true'
        config['healthCheckPath'] = request.form.get('healthCheckPath', '/')
        config['autoRestart'] = request.form.get('autoRestart', 'true').lower() == 'true'
        
        dep_id = str(uuid.uuid4())[:8]
        upload_path = f"./uploads/{dep_id}"
        os.makedirs(upload_path, exist_ok=True)
        
        filename = secure_filename(file.filename)
        file_path = os.path.join(upload_path, filename)
        file.save(file_path)
        
        proj_dir = f"./deployments/{dep_id}"
        os.makedirs(proj_dir, exist_ok=True)
        
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            zip_ref.extractall(proj_dir)
        
        extracted_files = os.listdir(proj_dir)
        if len(extracted_files) == 1 and os.path.isdir(os.path.join(proj_dir, extracted_files[0])):
            sub_dir = os.path.join(proj_dir, extracted_files[0])
            for item in os.listdir(sub_dir):
                shutil.move(os.path.join(sub_dir, item), proj_dir)
            os.rmdir(sub_dir)
            
        volume_name = None
        if config.get('persistentStorage'):
            volume_name = f"persistent_data_{dep_id}"
            config['volumeName'] = volume_name
        
        deployment_record = {
            'id': dep_id,
            'projectName': project_name,
            'deploymentType': deployment_type,
            'status': 'queued',
            'url': f"/deploy/{dep_id}/",
            'directUrl': None,
            'timestamp': datetime.now().isoformat(),
            'containerId': None,
            'port': None,
            'source': 'local',
            'filename': filename,
            'config': config,
            'environmentVariables': config['environmentVariables'],
            'version': 1,
            'healthCheckPath': config['healthCheckPath'],
            'volumePath': volume_name,
            'customDomain': None
        }
        
        db_manager.save_deployment(deployment_record)
        save_deployment_version(deployment_record)
        
        # Queue Job
        q.enqueue(
            run_deployment_task,
            args=(dep_id, proj_dir, deployment_type, config),
            job_timeout='15m',
            result_ttl=86400
        )
        
        shutil.rmtree(upload_path)
        
        return jsonify(deployment_record), 200
    
    except Exception as e:
        logger.error(f"Local deployment error: {traceback.format_exc()}")
        return jsonify({'error': str(e)}), 500

###############################################
# Deployment Management
###############################################

@app.route('/api/deployments', methods=['GET'])
@rate_limit(limit_type='api')
def get_deployments():
    try:
        deployments = db_manager.get_all_deployments()
        for deployment in deployments:
            if deployment.get('containerId'):
                docker_status = docker_manager.get_container_status(deployment['containerId'])
                current_status = deployment.get('status')
                if current_status not in ['building', 'queued'] and docker_status != 'not_found':
                    new_status = 'active' if docker_status == 'running' else docker_status
                    if new_status != current_status:
                        deployment['status'] = new_status
                        db_manager.save_deployment(deployment)
        return jsonify(deployments), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>', methods=['GET'])
@rate_limit(limit_type='api')
def get_deployment(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        if dep.get('containerId'):
            docker_status = docker_manager.get_container_status(dep['containerId'])
            if dep.get('status') not in ['building', 'queued']:
                new_status = 'active' if docker_status == 'running' else docker_status
                dep['status'] = new_status
                db_manager.save_deployment(dep)
        
        dep['versions'] = db_manager.get_deployment_versions(deployment_id)
        return jsonify(dep), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>', methods=['DELETE'])
@rate_limit(limit_type='api')
def delete_deployment(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        if dep.get('containerId'):
            docker_manager.stop_container(dep['containerId'])
        
        versions = db_manager.get_deployment_versions(deployment_id)
        for version in versions:
            try:
                docker_manager.stop_container(version['containerId'])
            except:
                pass
        
        try:
            if dep.get('volumePath'):
                vol = docker_manager.client.volumes.get(dep['volumePath'])
                vol.remove(force=True)
        except:
            pass
        
        db_manager.delete_deployment(deployment_id)
        return jsonify({'message': 'Deployment deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/logs', methods=['GET'])
@rate_limit(limit_type='api')
def get_logs(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        if dep.get('status') in ['building', 'queued']:
            logs = redis_conn.lrange(f"logs:{deployment_id}", 0, -1)
            parsed_logs = []
            for l in logs:
                if isinstance(l, bytes): l = l.decode('utf-8')
                try:
                    parsed_logs.append(json.loads(l).get('message', ''))
                except:
                    parsed_logs.append(l)
            return jsonify({'logs': "\n".join(parsed_logs)}), 200

        tail = request.args.get('tail', 100, type=int)
        logs = docker_manager.get_container_logs(dep['containerId'], tail=tail)
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/restart', methods=['POST'])
@rate_limit(limit_type='api')
def restart_deployment(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        container = docker_manager.client.containers.get(dep['containerId'])
        container.restart(timeout=10)
        
        return jsonify({'message': 'Deployment restarted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/stats', methods=['GET'])
@rate_limit(limit_type='api')
def get_deployment_stats(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        stats = docker_manager.get_container_stats(dep['containerId'])
        if stats:
            save_metrics(deployment_id, stats)
            return jsonify(stats), 200
        return jsonify({'error': 'Stats unavailable'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/metrics', methods=['GET'])
@rate_limit(limit_type='api')
def get_deployment_metrics(deployment_id):
    try:
        hours = request.args.get('hours', 24, type=int)
        metrics = db_manager.get_metrics(deployment_id, hours)
        return jsonify({'metrics': metrics}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/rollback', methods=['POST'])
@rate_limit(limit_type='api')
def rollback_deployment(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        history = db_manager.get_deployment_versions(deployment_id)
        if not history:
            return jsonify({'error': 'No previous versions available'}), 400
        
        data = request.json or {}
        target_version = data.get('version')
        
        if target_version:
            target = next((v for v in history if v['version'] == target_version), None)
            if not target:
                return jsonify({'error': f'Version {target_version} not found'}), 404
        else:
            target = history[-1]
        
        docker_manager.stop_container(dep['containerId'])
        
        try:
            old_container = docker_manager.client.containers.get(target['containerId'])
            old_container.start()
            
            dep['containerId'] = target['containerId']
            dep['config'] = target['config']
            dep['timestamp'] = datetime.now().isoformat()
            dep['version'] = target['version']
            
            db_manager.save_deployment(dep)
            
            return jsonify({
                'message': f"Rolled back to version {target['version']}",
                'deployment': dep
            }), 200
        except Exception as e:
            return jsonify({'error': f'Rollback failed: {str(e)}'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/env', methods=['PUT'])
@rate_limit(limit_type='api')
def update_environment_variables(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        data = request.json
        env_vars = data.get('environmentVariables', [])
        
        dep['config']['environmentVariables'] = env_vars
        dep['environmentVariables'] = env_vars
        
        db_manager.save_deployment(dep)
        
        container = docker_manager.client.containers.get(dep['containerId'])
        container.restart(timeout=10)
        
        return jsonify({
            'message': 'Environment variables updated (container restarted)',
            'deployment': dep
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/domain', methods=['POST'])
@rate_limit(limit_type='api')
def add_custom_domain(deployment_id):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        data = request.json
        domain = data.get('domain')
        cloudflare_api_key = data.get('cloudflareApiKey')
        cloudflare_zone_id = data.get('cloudflareZoneId')
        
        if not all([domain, cloudflare_api_key, cloudflare_zone_id]):
            return jsonify({'error': 'Domain, API key, and Zone ID required'}), 400
        
        headers = {
            'Authorization': f'Bearer {cloudflare_api_key}',
            'Content-Type': 'application/json'
        }
        
        dns_record = {
            'type': 'A',
            'name': domain,
            'content': '127.0.0.1', 
            'ttl': 1,
            'proxied': True
        }
        
        response = requests.post(
            f'https://api.cloudflare.com/client/v4/zones/{cloudflare_zone_id}/dns_records',
            headers=headers,
            json=dns_record
        )
        
        if response.status_code == 200:
            dep['customDomain'] = {'domain': domain, 'status': 'active'}
            db_manager.save_deployment(dep)
            return jsonify({'message': f'Custom domain {domain} added', 'deployment': dep}), 200
        else:
            return jsonify({'error': f'Cloudflare API error: {response.text}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cleanup', methods=['POST'])
def cleanup_stopped():
    try:
        removed = docker_manager.cleanup_stopped_containers()
        return jsonify({'message': f'Removed {removed} stopped containers'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/deploy/<deployment_id>/', defaults={'path': ''})
@app.route('/deploy/<deployment_id>/<path:path>')
def proxy(deployment_id, path=''):
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        mapped_port = dep.get('port')
        if not mapped_port:
            return jsonify({'error': 'Port not found for deployment'}), 404
        
        try:
            host = socket.gethostbyname('host.docker.internal')
        except:
            host = 'localhost'
        target_url = f"http://{host}:{mapped_port}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string.decode()}"
        
        headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'connection']}
        
        resp = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            timeout=30
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [
            (name, value) for name, value in resp.raw.headers.items()
            if name.lower() not in excluded_headers
        ]
        
        return Response(resp.content, resp.status_code, response_headers)
    
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Service timeout'}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Service unavailable'}), 503
    except Exception as e:
        return jsonify({'error': f'Proxy error: {str(e)}'}), 502

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, werkzeug.exceptions.HTTPException):
        return jsonify({'error': e.description}), e.code
    logger.error(f"Unhandled exception: {traceback.format_exc()}")
    return jsonify({'error': str(e), 'type': type(e).__name__}), 500

if __name__ == '__main__':
    logger.info("🚀 Deployment Platform v3.1 - Job Queue Enabled")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)