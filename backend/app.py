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
import queue
import threading
import signal
import sys
import sqlite3
import werkzeug.exceptions
from dotenv import load_dotenv
from pathlib import Path
from db_manager import DatabaseManager
from rate_limiter import rate_limit

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
# Load secret key from environment variable or use default (change in production!)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'change_this_secret_key_in_production')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400 * 7  # 7 days
cors_origins = os.getenv('CORS_ORIGINS', 'http://localhost:5173').split(',')
CORS(app, supports_credentials=True, origins=cors_origins)
###############################################
# GitHub Authentication and Repo Endpoints
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
        # Store token in session for persistent login
        session['github_token'] = token
        session['github_user'] = user.login
        session.permanent = True  # Make session persistent
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
            # Get default branch
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
    """Check if user has an active GitHub session"""
    token = session.get('github_token')
    username = session.get('github_user')
    if token and username:
        try:
            # Verify token is still valid
            g = Github(token)
            user = g.get_user()
            return jsonify({'authenticated': True, 'username': user.login})
        except:
            # Token expired or invalid
            session.pop('github_token', None)
            session.pop('github_user', None)
            return jsonify({'authenticated': False})
    return jsonify({'authenticated': False})


app.config['MAX_CONTENT_LENGTH'] = 600 * 1024 * 1024  # 600MB
app.config['JSON_SORT_KEYS'] = False

# Initialize managers
try:
    docker_manager = DockerManager()
    github_handler = GitHubHandler()
    logger.info("✅ Managers initialized")
except Exception as e:
    logger.error(f"❌ Initialization failed: {str(e)}")
    sys.exit(1)

# In-memory storage (for build logs only)
build_logs_streams = {}

# Directory setup - Define folder constants
UPLOAD_FOLDER = 'uploads'
PROJECTS_FOLDER = 'projects'

# Create directories
for dir_path in ['./deployments', './uploads', './projects', './persistent_storage', './volumes', './db']:
    os.makedirs(dir_path, exist_ok=True)

    try:
        os.chmod(dir_path, 0o777)
    except:
        pass

# Initialize database manager (PostgreSQL or SQLite)
db_manager = DatabaseManager()
DB_PATH = './db/deployments.db'  # Keep for backward compatibility

ALLOWED_EXTENSIONS = {'zip'}
MAX_FILE_SIZE = 600 * 1024 * 1024

def get_host():
    try:
        return socket.gethostbyname('host.docker.internal')
    except:
        return 'localhost'

def emit_log(dep_id, message):
    if dep_id in build_logs_streams:
        try:
            build_logs_streams[dep_id].put(message, timeout=1)
        except queue.Full:
            pass
    logger.info(f"[{dep_id}] {message}")

def save_deployment_version(deployment):
    """Save deployment version for rollback"""
    dep_id = deployment['id']
    
    # Get existing versions to determine next version number
    existing_versions = db_manager.get_deployment_versions(dep_id)
    next_version = len(existing_versions) + 1
    
    version = {
        'version': next_version,
        'containerId': deployment['containerId'],
        'timestamp': deployment['timestamp'],
        'config': deployment.get('config', {}),
        'status': 'previous'
    }
    
    # Save to database
    db_manager.save_deployment_version(dep_id, version)
    
    # Keep only last 10 versions (cleanup old containers)
    if len(existing_versions) >= 10:
        # Get oldest version and stop its container
        oldest_version = existing_versions[-1]
        try:
            docker_manager.stop_container(oldest_version['containerId'])
        except:
            pass

def save_metrics(dep_id, stats):
    """Save deployment metrics to database"""
    db_manager.save_metrics(dep_id, stats)

@app.route('/api/health', methods=['GET'])
def health():
    """Enhanced health check"""
    try:
        docker_manager.client.ping()
        docker_healthy = True
    except:
        docker_healthy = False
    
    # Get deployment stats from database
    try:
        all_deployments = db_manager.get_all_deployments()
        active_count = sum(1 for d in all_deployments if d.get('status') == 'active')
        total_count = len(all_deployments)
    except:
        total_count = 0
        active_count = 0
    
    return jsonify({
        'status': 'healthy' if docker_healthy else 'unhealthy',
        'docker': 'connected' if docker_healthy else 'disconnected',
        'database': db_manager.db_type,
        'deployments': total_count,
        'active': active_count,
        'timestamp': datetime.now().isoformat(),
        'version': '3.0.0',
        'features': {
            'envVariables': True,
            'persistentStorage': True,
            'healthChecks': True,
            'autoRestart': True,
            'rollback': True,
            'metrics': True,
            'customDomains': True,
            'volumeSupport': True,
            'rateLimiting': True,
            'postgresql': db_manager.db_type == 'postgresql'
        }
    }), 200 if docker_healthy else 503

@app.route('/deploy/<deployment_id>/', defaults={'path': ''})
@app.route('/deploy/<deployment_id>/<path:path>')
def proxy(deployment_id, path=''):
    """Proxy with custom domain support"""
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        # Get the mapped port (this is the host port Docker assigned)
        mapped_port = dep.get('port')
        if not mapped_port:
            return jsonify({'error': 'Port not found for deployment'}), 404
        
        # Connect to the container via host.docker.internal (works from within Docker)
        # or use directUrl if available
        direct_url = dep.get('directUrl', f"http://localhost:{mapped_port}")
        # Extract port from directUrl or use mapped_port
        if direct_url and 'localhost:' in direct_url:
            target_url = direct_url.rstrip('/') + '/' + path if path else direct_url.rstrip('/')
        else:
            # Fallback: use host.docker.internal to access host ports from container
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

@app.route('/api/detect-project', methods=['POST'])
def detect_project_endpoint():
    """Auto-detect project type"""
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
            
            shutil.rmtree(temp_dir)
            
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
    """Auto-detect GitHub project"""
    try:
        data = request.json
        if not data.get('githubRepo'):
            return jsonify({'error': 'GitHub repository URL required'}), 400
        
        temp_id = str(uuid.uuid4())[:8]
        temp_dir = f"./uploads/temp-{temp_id}"
        
        try:
            # Get token from session if available
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
# ZIP Upload endpoint - ADD THIS NEW ROUTE
@app.route('/api/upload', methods=['POST'])
def upload_zip():
    """Handle ZIP file upload"""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.zip'):
            return jsonify({'error': 'Only ZIP files are allowed'}), 400
        
        # Generate unique ID
        upload_id = str(uuid.uuid4())
        upload_dir = os.path.join(UPLOAD_FOLDER, upload_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Save ZIP file
        zip_path = os.path.join(upload_dir, secure_filename(file.filename))
        logger.info(f"Saving ZIP file to: {zip_path}")
        file.save(zip_path)
        
        # Extract ZIP
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(upload_dir)
            logger.info(f"✅ ZIP extracted to: {upload_dir}")
        except zipfile.BadZipFile:
            shutil.rmtree(upload_dir, ignore_errors=True)
            return jsonify({'error': 'Invalid ZIP file'}), 400
        
        # Remove the ZIP file after extraction
        os.remove(zip_path)
        
        return jsonify({
            'success': True,
            'uploadId': upload_id,
            'path': upload_dir,
            'message': 'File uploaded and extracted successfully'
        }), 200
    
    except Exception as e:
        logger.error(f"❌ Upload error: {traceback.format_exc()}")
        # ✅ FIXED: Always return JSON, even on error
        return jsonify({
            'error': str(e),
            'type': type(e).__name__
        }), 500


@app.route('/api/deploy-stream', methods=['POST'])
@rate_limit(limit_type='deploy')
def deploy_stream():
    """Deploy with streaming logs - ENHANCED"""
    try:
        if not request.is_json:
            return jsonify({'error': 'Request must be JSON'}), 400
        
        data = request.json
        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400
        
        if not data.get('projectName') or not data.get('githubRepo'):
            return jsonify({'error': 'Project name and repository required'}), 400
    except Exception as e:
        logger.error(f"Error parsing deploy-stream request: {traceback.format_exc()}")
        return jsonify({'error': f'Invalid request: {str(e)}'}), 400
    
    dep_id = str(uuid.uuid4())[:8]
    build_logs_streams[dep_id] = queue.Queue(maxsize=1000)
    
    def generate():
        proj_dir = None
        try:
            msg = {'type': 'info', 'message': f'🚀 Starting deployment {dep_id}'}
            yield f"data: {json.dumps(msg)}\n\n"
            
            proj_dir = f"./deployments/{dep_id}"
            clone_msg = {'type': 'info', 'message': f"📥 Cloning: {data.get('githubRepo')}"}
            yield f"data: {json.dumps(clone_msg)}\n\n"
            
            # Use temporary directory for cloning - original repo is never modified
            branch = data.get('branch', 'main')
            # Get token from session if available (for logged-in users)
            token = session.get('github_token')
            try:
                github_handler.clone_repo(data['githubRepo'], proj_dir, branch, token=token)
                success_msg = {'type': 'success', 'message': f'✅ Repository cloned (branch: {branch})'}
                yield f"data: {json.dumps(success_msg)}\n\n"
            except Exception as clone_error:
                error_message = str(clone_error)
                # Check if it's an authentication error for private repo
                if 'authentication' in error_message.lower() or 'permission denied' in error_message.lower() or 'not found' in error_message.lower():
                    if not token:
                        error_message = "❌ Private repository detected. Please log in with GitHub to deploy private repos."
                    else:
                        error_message = f"❌ Authentication failed. Please check your GitHub token has access to this repository. Error: {error_message}"
                
                error_msg = {'type': 'error', 'message': error_message}
                yield f"data: {json.dumps(error_msg)}\n\n"
                done_msg = {'type': 'done', 'success': False, 'error': error_message}
                yield f"data: {json.dumps(done_msg)}\n\n"
                return
            
            deployment_type = data['deploymentType']
            config = data.get('config', {})
            
            # Enhanced features
            config['environmentVariables'] = data.get('environmentVariables', [])
            config['persistentStorage'] = data.get('persistentStorage', False)
            config['healthCheckPath'] = data.get('healthCheckPath', '/')
            config['autoRestart'] = data.get('autoRestart', True)
            
            # Detect project type and enforce Django persistent storage
            detector = ProjectDetector(proj_dir)
            detection = detector.detect_all()
            if detection.get('framework') == 'django':
                # Ensure Django default port 8000
                try:
                    if not config.get('port') or str(config.get('port')) in ['5000', '']:
                        config['port'] = '8000'
                except Exception:
                    config['port'] = '8000'
                if not config.get('persistentStorage'):
                    error_message = "Django requires persistent storage (for SQLite/static/media). Enable 'Persistent Storage'."
                    yield f"data: {json.dumps({'type':'error','message':'❌ ' + error_message})}\n\n"
                    yield f"data: {json.dumps({'type':'done','success': False, 'error': error_message})}\n\n"
                    return
            # Create named volume if requested
            volume_name = None
            if config.get('persistentStorage'):
                volume_name = f"persistent_data_{dep_id}"
                config['volumeName'] = volume_name
                vol_msg = {'type': 'info', 'message': f"💾 Using named volume '{volume_name}'"}
                yield f"data: {json.dumps(vol_msg)}\n\n"
            
            build_msg = {'type': 'info', 'message': '🔨 Building Docker image...'}
            yield f"data: {json.dumps(build_msg)}\n\n"
            
            result_container = {'success': False, 'container_id': None, 'port': None, 'error': None}
            
            def deploy_worker():
                try:
                    if deployment_type == 'static':
                        container_id, port = docker_manager.deploy_static_site(
                            proj_dir, dep_id, config, log_callback=lambda msg: emit_log(dep_id, msg)
                        )
                    else:
                        container_id, port = docker_manager.deploy_web_service(
                            proj_dir, dep_id, config, log_callback=lambda msg: emit_log(dep_id, msg)
                        )
                    
                    result_container['success'] = True
                    result_container['container_id'] = container_id
                    result_container['port'] = port
                except Exception as e:
                    result_container['error'] = str(e)
                    emit_log(dep_id, f"❌ Error: {str(e)}")
            
            deploy_thread = threading.Thread(target=deploy_worker)
            deploy_thread.start()
            
            while deploy_thread.is_alive() or not build_logs_streams[dep_id].empty():
                try:
                    log_msg = build_logs_streams[dep_id].get(timeout=0.5)
                    log_data = {'type': 'log', 'message': log_msg}
                    yield f"data: {json.dumps(log_data)}\n\n"
                except queue.Empty:
                    continue
            
            deploy_thread.join()
            
            if result_container['success']:
                deployment_record = {
                    'id': dep_id,
                    'projectName': data['projectName'],
                    'deploymentType': data['deploymentType'],
                    'status': 'active',
                    'url': f"/deploy/{dep_id}/",
                    'directUrl': f"http://localhost:{result_container['port']}",
                    'timestamp': datetime.now().isoformat(),
                    'containerId': result_container['container_id'],
                    'port': result_container['port'],
                    'source': 'github',
                    'repo': data['githubRepo'],
                    'branch': data.get('branch', 'main'),
                    'config': config,
                    'environmentVariables': config['environmentVariables'],
                    'version': 1,
                    'healthCheckPath': config['healthCheckPath'],
                    'autoRestart': config['autoRestart'],
                    'volumePath': volume_name,
                    'customDomain': None
                }
                
                # Save to database
                db_manager.save_deployment(deployment_record)
                save_deployment_version(deployment_record)
                
                success_msg = {'type': 'success', 'message': f"✅ Deployed on port {result_container['port']}"}
                yield f"data: {json.dumps(success_msg)}\n\n"
                done_msg = {'type': 'done', 'success': True, 'deployment': deployment_record}
                yield f"data: {json.dumps(done_msg)}\n\n"
            else:
                error_msg = result_container.get('error', 'Unknown error')
                err_data = {'type': 'error', 'message': f'❌ Failed: {error_msg}'}
                yield f"data: {json.dumps(err_data)}\n\n"
                done_msg = {'type': 'done', 'success': False, 'error': error_msg}
                yield f"data: {json.dumps(done_msg)}\n\n"
        
        except Exception as e:
            error_data = {'type': 'error', 'message': f'❌ Error: {str(e)}'}
            yield f"data: {json.dumps(error_data)}\n\n"
            done_msg = {'type': 'done', 'success': False, 'error': str(e)}
            yield f"data: {json.dumps(done_msg)}\n\n"
        finally:
            if dep_id in build_logs_streams:
                del build_logs_streams[dep_id]
            if proj_dir and os.path.exists(proj_dir):
                shutil.rmtree(proj_dir)
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

@app.route('/api/deploy-local', methods=['POST'])
@rate_limit(limit_type='upload')
def deploy_local():
    """Deploy from ZIP - ENHANCED"""
    dep_id = None
    proj_dir = None
    
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        project_name = request.form.get('projectName')
        deployment_type = request.form.get('deploymentType')
        
        if not all([file.filename, project_name, deployment_type]):
            return jsonify({'error': 'Missing required fields'}), 400
        
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
        
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            os.remove(file_path)
            return jsonify({'error': 'File too large. Max: 600MB'}), 400
        
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
        
        # Detect project type and enforce Django persistent storage
        detector = ProjectDetector(proj_dir)
        detection = detector.detect_all()
        if detection.get('framework') == 'django':
            # Ensure Django default port 8000
            try:
                if not config.get('port') or str(config.get('port')) in ['5000', '']:
                    config['port'] = '8000'
            except Exception:
                config['port'] = '8000'
            if not config.get('persistentStorage'):
                if os.path.exists(upload_path):
                    shutil.rmtree(upload_path)
                shutil.rmtree(proj_dir, ignore_errors=True)
                return jsonify({'error': "Django requires persistent storage (for SQLite/static/media). Enable 'Persistent Storage'."}), 400

        # Create named volume if needed
        volume_name = None
        if config.get('persistentStorage'):
            volume_name = f"persistent_data_{dep_id}"
            config['volumeName'] = volume_name
        
        if deployment_type == 'static':
            container_id, port = docker_manager.deploy_static_site(proj_dir, dep_id, config)
        else:
            container_id, port = docker_manager.deploy_web_service(proj_dir, dep_id, config)
        
        deployment_record = {
            'id': dep_id,
            'projectName': project_name,
            'deploymentType': deployment_type,
            'status': 'active',
            'url': f"/deploy/{dep_id}/",
            'directUrl': f"http://localhost:{port}",
            'timestamp': datetime.now().isoformat(),
            'containerId': container_id,
            'port': port,
            'source': 'local',
            'filename': filename,
            'config': config,
            'environmentVariables': config['environmentVariables'],
            'version': 1,
            'healthCheckPath': config['healthCheckPath'],
            'volumePath': volume_name,
            'customDomain': None
        }
        
        # Save to database
        db_manager.save_deployment(deployment_record)
        save_deployment_version(deployment_record)
        
        shutil.rmtree(upload_path)
        
        return jsonify(deployment_record), 200
    
    except Exception as e:
        logger.error(f"Local deployment error: {traceback.format_exc()}")
        if proj_dir and os.path.exists(proj_dir):
            shutil.rmtree(proj_dir)
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments', methods=['GET'])
@rate_limit(limit_type='api')
def get_deployments():
    """Get all deployments"""
    try:
        deployments = db_manager.get_all_deployments()
        
        # Update status from Docker
        for deployment in deployments:
            if deployment.get('containerId'):
                docker_status = docker_manager.get_container_status(deployment['containerId'])
                original_status = deployment.get('status')
                # Transform Docker status to deployment status
                new_status = 'active' if docker_status == 'running' else docker_status
                deployment['status'] = new_status
                # Update in database if status actually changed
                if new_status != original_status:
                    db_manager.save_deployment(deployment)
        
        return jsonify(deployments), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>', methods=['GET'])
@rate_limit(limit_type='api')
def get_deployment(deployment_id):
    """Get deployment with version history"""
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        docker_status = docker_manager.get_container_status(dep['containerId'])
        original_status = dep.get('status')
        # Transform Docker status to deployment status
        new_status = 'active' if docker_status == 'running' else docker_status
        dep['status'] = new_status
        dep['versions'] = db_manager.get_deployment_versions(deployment_id)
        
        # Update in database if status actually changed
        if new_status != original_status:
            db_manager.save_deployment(dep)
        
        return jsonify(dep), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>', methods=['DELETE'])
@rate_limit(limit_type='api')
def delete_deployment(deployment_id):
    """Delete deployment and cleanup"""
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        docker_manager.stop_container(dep['containerId'])
        
        # Cleanup versions
        versions = db_manager.get_deployment_versions(deployment_id)
        for version in versions:
            try:
                docker_manager.stop_container(version['containerId'])
            except:
                pass
        
        # Cleanup volume (named Docker volume if used)
        try:
            if dep.get('volumePath'):
                # Treat stored value as volume name for new deployments
                try:
                    vol = docker_manager.client.volumes.get(dep['volumePath'])
                    vol.remove(force=True)
                except Exception:
                    # Fallback: it might be a host path from older deployments
                    if os.path.exists(dep['volumePath']):
                        shutil.rmtree(dep['volumePath'])
        except Exception:
            pass
        
        # Delete from database
        db_manager.delete_deployment(deployment_id)
        
        return jsonify({'message': 'Deployment deleted successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/logs', methods=['GET'])
@rate_limit(limit_type='api')
def get_logs(deployment_id):
    """Get container logs"""
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        tail = request.args.get('tail', 100, type=int)
        logs = docker_manager.get_container_logs(dep['containerId'], tail=tail)
        
        return jsonify({'logs': logs}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/restart', methods=['POST'])
@rate_limit(limit_type='api')
def restart_deployment(deployment_id):
    """Restart deployment"""
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
    """Get real-time stats"""
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
    """Get historical metrics from database"""
    try:
        hours = request.args.get('hours', 24, type=int)
        metrics = db_manager.get_metrics(deployment_id, hours)
        return jsonify({'metrics': metrics}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/rollback', methods=['POST'])
@rate_limit(limit_type='api')
def rollback_deployment(deployment_id):
    """Rollback to previous version"""
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
        
        # Stop current
        docker_manager.stop_container(dep['containerId'])
        
        try:
            old_container = docker_manager.client.containers.get(target['containerId'])
            old_container.start()
            
            dep['containerId'] = target['containerId']
            dep['config'] = target['config']
            dep['timestamp'] = datetime.now().isoformat()
            dep['version'] = target['version']
            
            # Save updated deployment
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
    """Update environment variables"""
    try:
        dep = db_manager.get_deployment(deployment_id)
        if not dep:
            return jsonify({'error': 'Deployment not found'}), 404
        
        data = request.json
        env_vars = data.get('environmentVariables', [])
        
        dep['config']['environmentVariables'] = env_vars
        dep['environmentVariables'] = env_vars
        
        # Save to database
        db_manager.save_deployment(dep)
        
        # Restart with new env vars
        container = docker_manager.client.containers.get(dep['containerId'])
        container.restart(timeout=10)
        
        return jsonify({
            'message': 'Environment variables updated',
            'deployment': dep
        }), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/deployments/<deployment_id>/domain', methods=['POST'])
@rate_limit(limit_type='api')
def add_custom_domain(deployment_id):
    """Add custom domain with Cloudflare"""
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
        
        # Create Cloudflare DNS record
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
            # Save custom domain to database
            try:
                with db_manager.get_connection() as conn:
                    cursor = conn.cursor()
                    if db_manager.db_type == 'postgresql':
                        cursor.execute('''
                            INSERT INTO custom_domains 
                            (deployment_id, domain, cloudflare_zone_id, status, created_at)
                            VALUES (%s, %s, %s, %s, %s)
                            ON CONFLICT (domain) DO UPDATE SET
                                deployment_id = EXCLUDED.deployment_id,
                                status = EXCLUDED.status
                        ''', (deployment_id, domain, cloudflare_zone_id, 'active', datetime.now().isoformat()))
                    else:
                        cursor.execute('''
                            INSERT OR REPLACE INTO custom_domains 
                            (deployment_id, domain, cloudflare_zone_id, status, created_at)
                            VALUES (?, ?, ?, ?, ?)
                        ''', (deployment_id, domain, cloudflare_zone_id, 'active', datetime.now().isoformat()))
                    conn.commit()
            except Exception as e:
                logger.error(f"Failed to save custom domain: {str(e)}")
            
            dep['customDomain'] = {'domain': domain, 'status': 'active'}
            db_manager.save_deployment(dep)
            
            return jsonify({
                'message': f'Custom domain {domain} added successfully',
                'deployment': dep
            }), 200
        else:
            return jsonify({'error': f'Cloudflare API error: {response.text}'}), 500
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cleanup', methods=['POST'])
def cleanup_stopped():
    """Cleanup stopped containers"""
    try:
        removed = docker_manager.cleanup_stopped_containers()
        return jsonify({'message': f'Removed {removed} stopped containers'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    error_trace = traceback.format_exc()
    logger.error(f"Internal error: {error_trace}")
    # Return more detailed error in development, generic in production
    error_detail = error_trace if app.debug else 'Internal server error'
    return jsonify({
        'error': 'Internal server error',
        'detail': error_detail,
        'traceback': error_trace if app.debug else None
    }), 500

@app.errorhandler(413)
def request_entity_too_large(e):
    return jsonify({'error': 'File too large. Max: 600MB'}), 413

def signal_handler(sig, frame):
    logger.info("🛑 Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# ✅ FIXED: Global error handler
@app.errorhandler(Exception)
def handle_exception(e):
    """Global exception handler"""
    error_trace = traceback.format_exc()
    logger.error(f"Unhandled exception: {error_trace}")
    
    if isinstance(e, werkzeug.exceptions.HTTPException):
        return jsonify({'error': e.description}), e.code
    
    # Provide more detailed error information
    error_response = {
        'error': str(e),
        'type': type(e).__name__,
        'message': str(e)
    }
    
    # Add traceback in debug mode
    if app.debug:
        error_response['traceback'] = error_trace
    
    return jsonify(error_response), 500


if __name__ == '__main__':
    logger.info("🚀 Deployment Platform v3.0 - Full Render Features")
    logger.info("✅ Features: Env Vars, Rollback, Metrics, Volumes, Custom Domains")
    
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
