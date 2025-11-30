import docker
import os
import shlex
from time import sleep
import logging
import json
import re
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

class DockerManager:
    def __init__(self):
        try:
            self.client = docker.DockerClient(base_url='unix:///var/run/docker.sock')
            self.client.ping()
            logger.info("✅ Connected to Docker daemon via socket")
        except Exception as e:
            logger.warning(f"⚠️ Socket connection failed, trying environment: {str(e)}")
            try:
                self.client = docker.from_env()
                self.client.ping()
                logger.info("✅ Connected to Docker daemon via environment")
            except Exception as e2:
                logger.error(f"❌ Failed to connect to Docker daemon: {str(e2)}")
                raise Exception(f"Cannot connect to Docker daemon. Is Docker running? Error: {str(e2)}")

    def deploy_static_site(self, project_dir, deployment_id, config, log_callback=None):
        """Deploy a static site with full Node.js version support"""
        def log(message):
            if log_callback:
                log_callback(message)
            logger.info(message)

        try:
            log("🔍 Analyzing project structure...")
            # Build command is optional - use default if not provided
            build_command = config.get('buildCommand', '')
            if not build_command or build_command.strip() == '':
                build_command = 'npm install && npm run build'
            publish_dir = config.get('publishDir', 'dist')
            entry_file = config.get('entryFile', 'index.html')  # Static entry file
            has_package_json = os.path.exists(f"{project_dir}/package.json")
            node_version = '22'

            if not has_package_json:
                publish_dir = '.'
                build_command = 'echo "No build needed for static HTML"'
                log("📄 No package.json found, treating as static HTML")
            else:
                log(f"🔨 Original build command: {build_command}")
                log(f"📂 Publish directory: {publish_dir}")

                # Auto-detect Node version from package.json
                try:
                    with open(f"{project_dir}/package.json", 'r') as f:
                        pkg_data = json.load(f)
                    
                    # Check engines.node
                    if 'engines' in pkg_data and 'node' in pkg_data['engines']:
                        node_req = pkg_data['engines']['node']
                        log(f"🔧 Found Node requirement: {node_req}")
                        
                        # Parse version requirement
                        cleaned = node_req.replace('^', '').replace('~', '').replace('>=', '').replace('>', '').replace('=', '').strip()
                        match = re.search(r'(\d+)', cleaned)
                        if match:
                            required_version = int(match.group(1))
                            if required_version >= 22:
                                node_version = '22'
                            elif required_version >= 20:
                                node_version = '20'
                            elif required_version >= 18:
                                node_version = '18'
                            elif required_version >= 16:
                                node_version = '16'
                            else:
                                node_version = '18'
                        log(f"📦 Using Node.js {node_version} (required: {node_req})")
                    else:
                        log(f"📦 No Node version specified, using Node.js {node_version}")
                except Exception as e:
                    log(f"⚠️ Could not detect Node version, using default {node_version}: {str(e)}")

                # Add --legacy-peer-deps for better compatibility
                if 'npm install' in build_command and '--legacy-peer-deps' not in build_command and '--force' not in build_command:
                    build_command = build_command.replace('npm install', 'npm install --legacy-peer-deps')
                    log(f"📦 Auto-enabled --legacy-peer-deps for better compatibility")

                log(f"🔨 Final build command: {build_command}")

            # Create comprehensive .dockerignore
            dockerignore_content = '''node_modules/
npm-debug.log
yarn-error.log
package-lock.json
yarn.lock
.git/
.gitignore
.vscode/
.idea/
*.swp
.DS_Store
Thumbs.db
.env
.env.local
.env.*.local
*.log
.cache/
.next/
.nuxt/
.output/
dist-ssr/
README.md
docs/
coverage/
.nyc_output/
'''
            # Write .dockerignore file
            dockerignore_path = f"{project_dir}/.dockerignore"
            with open(dockerignore_path, 'w') as f:
                f.write(dockerignore_content)
            log(f"✅ Created .dockerignore file")

            # Create nginx configuration
            nginx_conf = '''server {
    listen 80;
    listen [::]:80;
    
    root /usr/share/nginx/html;
    index index.html index.htm;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    gzip on;
    gzip_vary on;
    gzip_min_length 1024;
    gzip_types text/plain text/css text/xml text/javascript application/javascript application/json application/xml+rss font/truetype font/opentype image/svg+xml;
    
    location / {
        try_files $uri $uri/ /index.html;
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Access-Control-Allow-Origin "*" always;
    }
    
    location ~* \\.css$ {
        add_header Content-Type "text/css" always;
        add_header Cache-Control "public, max-age=31536000" always;
    }
    
    location ~* \\.(js|mjs|jsx)$ {
        add_header Content-Type "application/javascript" always;
        add_header Cache-Control "public, max-age=31536000" always;
    }
    
    location ~* \\.(jpg|jpeg|png|gif|ico|svg|webp)$ {
        add_header Cache-Control "public, max-age=31536000" always;
    }
    
    error_page 404 /index.html;
}'''
            with open(f"{project_dir}/default.conf", 'w') as f:
                f.write(nginx_conf)

            # ✅ FIXED: Create optimized Dockerfile with corrected COPY paths
            if has_package_json:
                dockerfile = f'''# Build stage
FROM node:{node_version}-alpine as builder
WORKDIR /app

# Install dependencies first (better caching)
COPY package*.json ./
RUN npm install --legacy-peer-deps --loglevel=error || npm install --force --loglevel=error || npm install --loglevel=error

# Copy source files
COPY . .

# Run build command
RUN {build_command}

# Smart HTML file detection
RUN if [ ! -f {publish_dir}/index.html ]; then \\
  echo "⚠️ index.html not found in {publish_dir}/, searching for alternative HTML files..." && \\
  HTML_FILE=$(find {publish_dir} -maxdepth 2 -type f -name "*.html" | head -n 1) && \\
  if [ -n "$HTML_FILE" ]; then \\
    HTML_NAME=$(basename "$HTML_FILE") && \\
    echo "✅ Found $HTML_NAME, copying to index.html" && \\
    cp "$HTML_FILE" {publish_dir}/index.html; \\
  else \\
    echo "❌ ERROR: No HTML files found in {publish_dir}/" && \\
    echo "📂 Directory contents:" && \\
    ls -la {publish_dir}/ && \\
    find {publish_dir} -type f -name "*.html" && \\
    exit 1; \\
  fi; \\
else \\
  echo "✅ index.html found in {publish_dir}/"; \\
fi

# Production stage
FROM nginx:alpine

# ✅ FIXED: Copy files correctly - removed the fallback that was causing errors
COPY --from=builder /app/{publish_dir} /usr/share/nginx/html/
COPY --from=builder /app/default.conf /etc/nginx/conf.d/default.conf

# Verify files are present
RUN echo "📂 Files in nginx html directory:" && ls -la /usr/share/nginx/html/ && \\
  echo "✅ Static site ready to serve"

EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD wget --quiet --tries=1 --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
'''
            else:
                # Pure static HTML without build step
                dockerfile = f'''FROM nginx:alpine
WORKDIR /usr/share/nginx/html

# Copy all files
COPY . .

# Copy nginx configuration
COPY default.conf /etc/nginx/conf.d/default.conf

# Smart HTML file detection
RUN if [ ! -f /usr/share/nginx/html/index.html ]; then \\
  echo "⚠️ index.html not found, searching for alternative HTML files..." && \\
  HTML_FILE=$(find /usr/share/nginx/html -maxdepth 2 -type f -name "*.html" | head -n 1) && \\
  if [ -n "$HTML_FILE" ]; then \\
    HTML_NAME=$(basename "$HTML_FILE") && \\
    echo "✅ Found $HTML_NAME, copying to index.html" && \\
    cp "$HTML_FILE" /usr/share/nginx/html/index.html; \\
  else \\
    echo "❌ ERROR: No HTML files found" && \\
    ls -la /usr/share/nginx/html/ && \\
    exit 1; \\
  fi; \\
else \\
  echo "✅ index.html found"; \\
fi

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD wget --quiet --tries=1 --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
'''

            with open(f"{project_dir}/Dockerfile", 'w') as f:
                f.write(dockerfile)

            # Clean up old container and image if exists
            try:
                old_container_name = f"deploy-{deployment_id}"
                try:
                    old_container = self.client.containers.get(old_container_name)
                    log(f"🧹 Removing old container: {old_container_name}")
                    old_container.stop(timeout=5)
                    old_container.remove(force=True)
                except docker.errors.NotFound:
                    pass
                
                # Try to remove old image
                try:
                    old_image = self.client.images.get(f"deploy-{deployment_id}")
                    log(f"🧹 Removing old image: deploy-{deployment_id}")
                    self.client.images.remove(old_image.id, force=True)
                except docker.errors.ImageNotFound:
                    pass
                except docker.errors.APIError:
                    # Image might be in use, ignore
                    pass
            except Exception as e:
                log(f"⚠️ Cleanup warning: {str(e)}")
            
            # Build Docker image
            log("🔨 Building Docker image...")
            try:
                image, build_logs = self.client.images.build(
                    path=project_dir,
                    tag=f"deploy-{deployment_id}",
                    rm=True,
                    forcerm=True,
                    nocache=False,
                    buildargs={'BUILDKIT_INLINE_CACHE': '1'}
                )

                for log_entry in build_logs:
                    if isinstance(log_entry, dict):
                        if 'stream' in log_entry:
                            msg = log_entry['stream'].strip()
                            if msg:
                                log(msg)
                        elif 'error' in log_entry:
                            log(f"❌ {log_entry['error']}")
                            raise Exception(log_entry['error'])
                    elif isinstance(log_entry, str):
                        log(log_entry)

                log("✅ Image built successfully")
            except docker.errors.BuildError as e:
                log(f"❌ Build failed: {str(e)}")
                if hasattr(e, 'build_log'):
                    for line in e.build_log:
                        if isinstance(line, dict) and 'stream' in line:
                            log(line['stream'].strip())
                raise Exception(f"Docker build failed: {str(e)}")

            # Setup volumes for persistent storage (support named volumes)
            volumes = {}
            if config.get('persistentStorage'):
                volume_name = config.get('volumeName')
                if volume_name:
                    # Ensure named volume exists
                    try:
                        self.client.volumes.get(volume_name)
                    except Exception:
                        self.client.volumes.create(name=volume_name)
                    volumes[volume_name] = {'bind': '/app/data', 'mode': 'rw'}
                    log(f"💾 Mounting named volume: {volume_name} -> /app/data")
                elif config.get('volumePath'):
                    volume_path = config['volumePath']
                    volumes[volume_path] = {'bind': '/app/data', 'mode': 'rw'}
                    log(f"💾 Mounting persistent storage: {volume_path} -> /app/data")
            
            # Run container
            log("🚀 Starting container...")
            try:
                container = self.client.containers.run(
                    image.id,
                    detach=True,
                    ports={'80/tcp': None},
                    name=f"deploy-{deployment_id}",
                    restart_policy={"Name": "unless-stopped"},
                    volumes=volumes,
                    remove=False,
                    labels={
                        'app': 'deployment-platform',
                        'type': 'static',
                        'deployment_id': deployment_id
                    }
                )

                # Wait for container to be ready
                for i in range(15):
                    sleep(1)
                    container.reload()
                    if container.status == 'running':
                        log(f"✅ Container is running ({i+1}s)")
                        break
                    log(f"⏳ Waiting for container... ({i+1}/15)")

                container.reload()
                if container.status != 'running':
                    logs_text = container.logs(tail=100)
                    if isinstance(logs_text, bytes):
                        logs_text = logs_text.decode('utf-8', errors='ignore')
                    log(f"❌ Container failed. Status: {container.status}")
                    log("📋 Container logs:")
                    for line in logs_text.split('\n'):
                        if line.strip():
                            log(line)
                    container.remove(force=True)
                    raise Exception(f"Container exited with status: {container.status}")

                port = container.attrs['NetworkSettings']['Ports']['80/tcp'][0]['HostPort']
                log(f"✅ Static site deployed successfully!")
                log(f"🌐 Access at: http://localhost:{port}")
                log(f"📦 Container ID: {container.id[:12]}")
                
                return container.id, port

            except Exception as e:
                log(f"❌ Container start failed: {str(e)}")
                try:
                    container.remove(force=True)
                except:
                    pass
                raise

        except Exception as e:
            log(f"❌ Static site deployment failed: {str(e)}")
            raise
    def deploy_web_service(self, proj_dir, dep_id, config, log_callback=None):
        """Deploy web service - Python (Flask/Django/FastAPI), Node.js, or Java"""
        def log(message):
            if log_callback:
                log_callback(message)
            logger.info(message)

        try:
            runtime = config.get('runtime', 'python')
            entry_file = config.get('entryFile', 'app.py')
            port = config.get('port', '5000')
            start_command = config.get('startCommand', '').strip()
            use_dev_mode = config.get('useDevMode', False)

            log(f"⚙️ Runtime: {runtime}, Entry: {entry_file}, Port: {port}")

            # Handle Java separately
            if runtime == 'java':
                log("☕ Detected Java runtime")
                return self.deploy_java_service(proj_dir, dep_id, config, log_callback)

            # Handle Node.js dev mode
            if use_dev_mode and runtime == 'nodejs':
                log("🔥 Development mode enabled - using npm run dev")
                return self._deploy_nodejs_dev(proj_dir, dep_id, port, config, log_callback)

            # Create .dockerignore based on runtime
            if runtime == 'python':
                dockerignore_content = '''__pycache__/
*.py[cod]
*.pyo
*.pyd
.Python
*.so
*.egg
*.egg-info/
dist/
build/
venv/
env/
.venv
ENV/
.git/
.gitignore
.vscode/
.idea/
.DS_Store
*.log
.pytest_cache/
.coverage
htmlcov/
.tox/
.mypy_cache/
.ruff_cache/
README.md
docs/
tests/
migrations/
'''
            else:  # Node.js
                dockerignore_content = '''node_modules/
npm-debug.log
yarn-error.log
.git/
.gitignore
.vscode/
.idea/
.DS_Store
*.log
.env
.env.local
.next/
.nuxt/
dist/
build/
coverage/
README.md
docs/
'''

            # Write .dockerignore file
            dockerignore_path = f"{proj_dir}/.dockerignore"
            with open(dockerignore_path, 'w') as f:
                f.write(dockerignore_content)
            log(f"✅ Created .dockerignore file")

            # Build Dockerfile based on runtime
            build_command = config.get('buildCommand', '').strip()
            if runtime == 'python':
                dockerfile = self._create_python_dockerfile(proj_dir, entry_file, port, start_command, build_command, log)
            else:  # Node.js (production mode)
                dockerfile = self._create_nodejs_dockerfile(proj_dir, entry_file, port, start_command, build_command, log)

            with open(f"{proj_dir}/Dockerfile", 'w') as f:
                f.write(dockerfile)

            # Clean up old container and image if exists
            try:
                old_container_name = f"web-{dep_id}"
                try:
                    old_container = self.client.containers.get(old_container_name)
                    log(f"🧹 Removing old container: {old_container_name}")
                    old_container.stop(timeout=5)
                    old_container.remove(force=True)
                except docker.errors.NotFound:
                    pass
                
                # Try to remove old image
                try:
                    old_image = self.client.images.get(f"web-{dep_id}")
                    log(f"🧹 Removing old image: web-{dep_id}")
                    self.client.images.remove(old_image.id, force=True)
                except docker.errors.ImageNotFound:
                    pass
                except docker.errors.APIError:
                    # Image might be in use, ignore
                    pass
            except Exception as e:
                log(f"⚠️ Cleanup warning: {str(e)}")
            
            # Build Docker image
            log("🔨 Building Docker image...")
            try:
                img, build_logs = self.client.images.build(
                    path=proj_dir,
                    tag=f"web-{dep_id}",
                    rm=True,
                    forcerm=True,
                    nocache=False
                )

                for log_entry in build_logs:
                    if isinstance(log_entry, dict):
                        if 'stream' in log_entry:
                            msg = log_entry['stream'].strip()
                            if msg:
                                log(msg)
                        elif 'error' in log_entry:
                            log(f"❌ {log_entry['error']}")
                            raise Exception(log_entry['error'])
                    elif isinstance(log_entry, str):
                        log(log_entry)

                log("✅ Image built successfully")
            except docker.errors.BuildError as e:
                log(f"❌ Build failed: {str(e)}")
                if hasattr(e, 'build_log'):
                    for line in e.build_log:
                        if isinstance(line, dict) and 'stream' in line:
                            log(line['stream'].strip())
                raise Exception(f"Docker build failed: {str(e)}")

                # Run container
            log("🚀 Starting web service container...")
            try:
                env_vars = {
                    'PORT': port,
                    'PYTHONUNBUFFERED': '1' if runtime == 'python' else '',
                    'NODE_ENV': 'production' if runtime == 'nodejs' else ''
                }

                # Add Flask/Django specific vars
                # Initialize Django detection variables outside the if block for later use
                user_provided_django_settings = False
                is_django_for_env = False
                
                if runtime == 'python':
                    # Check if user provided DJANGO_SETTINGS_MODULE in environment variables
                    if config.get('environmentVariables'):
                        for env_var in config['environmentVariables']:
                            if env_var.get('key') == 'DJANGO_SETTINGS_MODULE':
                                user_provided_django_settings = True
                                log(f"🔧 User provided DJANGO_SETTINGS_MODULE: {env_var.get('value')}")
                                break
                    
                    # Detect Django to set correct settings module (only if user didn't provide it)
                    django_settings_module = 'settings'
                    
                    if not user_provided_django_settings:
                        is_django_for_env = False
                        try:
                            for root, dirs, files in os.walk(proj_dir):
                                if 'manage.py' in files:
                                    is_django_for_env = True
                                    # Find Django project name
                                    for d in dirs:
                                        settings_path = os.path.join(root, d, 'settings.py')
                                        if os.path.exists(settings_path):
                                            django_settings_module = f"{d}.settings_local"
                                            break
                                    if is_django_for_env and django_settings_module == 'settings':
                                        # Fallback: check requirements
                                        req_path = os.path.join(proj_dir, 'requirements.txt')
                                        if os.path.exists(req_path):
                                            with open(req_path, 'r') as f:
                                                if 'django' in f.read().lower():
                                                    # Try to find project name from manage.py
                                                    manage_path = os.path.join(root, 'manage.py')
                                                    if os.path.exists(manage_path):
                                                        with open(manage_path, 'r') as mf:
                                                            content = mf.read()
                                                            match = re.search(r'["\']DJANGO_SETTINGS_MODULE["\']\s*,\s*["\']([^"\']+)["\']', content)
                                                            if match:
                                                                project_name = match.group(1).split('.')[0]
                                                                django_settings_module = f"{project_name}.settings_local"
                                    break
                        except:
                            pass
                    
                    env_vars.update({
                        'FLASK_APP': entry_file,
                        'FLASK_RUN_HOST': '0.0.0.0',
                        'FLASK_RUN_PORT': port,
                    })
                    
                    # Only set DJANGO_SETTINGS_MODULE if user didn't provide it
                    if not user_provided_django_settings:
                        env_vars['DJANGO_SETTINGS_MODULE'] = django_settings_module
                        if is_django_for_env:
                            log(f"🔧 Auto-set DJANGO_SETTINGS_MODULE: {django_settings_module}")
                    else:
                        log(f"🔧 Using user-provided DJANGO_SETTINGS_MODULE")
                
                # Setup volumes for persistent storage (support named volumes)
                volumes = {}
                if config.get('persistentStorage'):
                    volume_name = config.get('volumeName')
                    if volume_name:
                        try:
                            self.client.volumes.get(volume_name)
                        except Exception:
                            self.client.volumes.create(name=volume_name)
                        volumes[volume_name] = {'bind': '/app/data', 'mode': 'rw'}
                        log(f"💾 Mounting named volume: {volume_name} -> /app/data")
                    elif config.get('volumePath'):
                        volume_path = config['volumePath']
                        volumes[volume_path] = {'bind': '/app/data', 'mode': 'rw'}
                        log(f"💾 Mounting persistent storage: {volume_path} -> /app/data")
                    
                    # For Django with persistent storage, set DATABASE_URL to SQLite by default
                    # Check if this is Django (either detected or user provided DJANGO_SETTINGS_MODULE)
                    # Also check if manage.py exists to detect Django
                    is_django_deployment = is_django_for_env or user_provided_django_settings
                    if not is_django_deployment:
                        # Double-check by looking for manage.py
                        try:
                            for root, dirs, files in os.walk(proj_dir):
                                if 'manage.py' in files:
                                    is_django_deployment = True
                                    break
                        except:
                            pass
                    
                    if is_django_deployment:
                        # Set DATABASE_URL to SQLite in persistent storage if not already set
                        has_db_url = False
                        if config.get('environmentVariables'):
                            for env_var in config['environmentVariables']:
                                if env_var.get('key') == 'DATABASE_URL':
                                    has_db_url = True
                                    break
                        
                        if not has_db_url:
                            env_vars['DATABASE_URL'] = 'sqlite:////app/data/db.sqlite3'
                            log(f"💾 Set DATABASE_URL to SQLite: sqlite:////app/data/db.sqlite3")
                
                # Add environment variables from config (after DATABASE_URL setup)
                if config.get('environmentVariables'):
                    for env_var in config['environmentVariables']:
                        if env_var.get('key') and env_var.get('value'):
                            env_vars[env_var['key']] = env_var['value']
                            log(f"🔧 Added env var: {env_var['key']}")
                
                # Resource limits for scalability
                mem_limit = os.getenv('CONTAINER_MEMORY_LIMIT', '512m')
                cpu_limit = os.getenv('CONTAINER_CPU_LIMIT', '0.5')
                
                cont = self.client.containers.run(
                    img.id,
                    detach=True,
                    ports={f'{port}/tcp': None},
                    name=f"web-{dep_id}",
                    restart_policy={"Name": "unless-stopped"},
                    environment=env_vars,
                    volumes=volumes,
                    remove=False,
                    mem_limit=mem_limit,
                    cpu_period=100000,
                    cpu_quota=int(float(cpu_limit) * 100000),
                    labels={
                        'app': 'deployment-platform',
                        'type': 'web-service',
                        'runtime': runtime,
                        'deployment_id': dep_id
                    }
                )

                # Wait for service to start - Django needs more time for migrations
                # Check if this is a Django deployment by looking for manage.py or django in requirements
                is_django_deployment = False
                if runtime == 'python':
                    try:
                        for root, dirs, files in os.walk(proj_dir):
                            if 'manage.py' in files:
                                is_django_deployment = True
                                break
                        if not is_django_deployment:
                            req_path = os.path.join(proj_dir, 'requirements.txt')
                            if os.path.exists(req_path):
                                with open(req_path, 'r') as f:
                                    if 'django' in f.read().lower():
                                        is_django_deployment = True
                    except:
                        pass
                
                wait_time = 40 if (runtime == 'python' and is_django_deployment) else (30 if runtime == 'python' else 15)
                log(f"⏳ Waiting for service to start ({wait_time} seconds)...")
                sleep(wait_time)

                cont.reload()
                if cont.status != 'running':
                    logs_text = cont.logs(tail=100)
                    if isinstance(logs_text, bytes):
                        logs_text = logs_text.decode('utf-8', errors='ignore')
                    log(f"❌ Container failed. Status: {cont.status}")
                    log("📋 Container logs:")
                    for line in logs_text.split('\n'):
                        if line.strip():
                            log(line)
                    cont.remove(force=True)
                    raise Exception(f"Container exited with status: {cont.status}")

                # Show startup logs
                logs_text = cont.logs(tail=30)
                if isinstance(logs_text, bytes):
                    logs_text = logs_text.decode('utf-8', errors='ignore')
                log("📋 Service startup logs:")
                for line in logs_text.split('\n')[-10:]:
                    if line.strip():
                        log(line)

                mapped_port = cont.attrs['NetworkSettings']['Ports'][f'{port}/tcp'][0]['HostPort']
                log(f"✅ Web service deployed successfully!")
                log(f"🌐 Access at: http://localhost:{mapped_port}")
                log(f"📦 Container ID: {cont.id[:12]}")
                
                return cont.id, mapped_port

            except Exception as e:
                log(f"❌ Container start failed: {str(e)}")
                try:
                    cont.reload()
                    logs_text = cont.logs(tail=100)
                    if isinstance(logs_text, bytes):
                        logs_text = logs_text.decode('utf-8', errors='ignore')
                    for line in logs_text.split('\n'):
                        if line.strip():
                            log(line)
                    cont.remove(force=True)
                except:
                    pass
                raise

        except Exception as e:
            log(f"❌ Web service deployment failed: {str(e)}")
            raise

    def _create_python_dockerfile(self, proj_dir, entry_file, port, start_command, build_command, log):
        """Create Python Dockerfile with proper Django detection"""
        has_requirements = os.path.exists(f"{proj_dir}/requirements.txt")
        has_pipfile = os.path.exists(f"{proj_dir}/Pipfile")
        
        if not has_requirements and not has_pipfile:
            log("⚠️ No requirements.txt or Pipfile found, creating default")
            with open(f"{proj_dir}/requirements.txt", 'w') as f:
                f.write("Flask==3.0.0\ngunicorn==21.2.0\n")
            has_requirements = True

        # Detect Django project structure (search recursively)
        django_project = None
        is_django = False
        manage_py_path = None
        # find manage.py anywhere
        for root, dirs, files in os.walk(proj_dir):
            if 'manage.py' in files:
                manage_py_path = os.path.join(root, 'manage.py')
                break
        
        try:
            if has_requirements:
                with open(f"{proj_dir}/requirements.txt", 'r') as f:
                    req_content = f.read().lower()
                is_django = 'django' in req_content
            elif has_pipfile:
                with open(f"{proj_dir}/Pipfile", 'r') as f:
                    pipfile_content = f.read().lower()
                is_django = 'django' in pipfile_content or has_manage_py
            
            if is_django and manage_py_path:
                with open(manage_py_path, 'r') as f:
                    manage_content = f.read()
                # Extract settings module from manage.py
                match = re.search(r'["\']DJANGO_SETTINGS_MODULE["\']\s*,\s*["\']([^"\']+)["\']', manage_content)
                if match:
                    django_project = match.group(1)
                    log(f"✅ Detected Django settings: {django_project}")
                else:
                    # Fallback: find directory with settings.py
                    for root, dirs, files in os.walk(proj_dir):
                        if 'settings.py' in files:
                            rel = os.path.relpath(root, proj_dir).replace('\\', '/').replace('/', '.')
                            if rel == '.':
                                continue
                            django_project = f"{rel}.settings"
                            log(f"✅ Found Django project: {django_project}")
                            break
        except Exception as e:
            log(f"⚠️ Django detection: {str(e)}")

        # Determine CMD based on framework
        runtime_prefix = ""
        pre_start = ""
        default_django_start = None
        requirements_text = ""
        procfile_cmd = None

        if is_django:
            runtime_prefix = "if [ -f .env ]; then export $(grep -v \"^#\" .env | xargs); fi; "
            pre_start = (
                "mkdir -p /app/data /app/data/staticfiles /app/data/media && "
                "echo '=== Django Startup ===' && "
                "echo 'Running migrations...' && python manage.py migrate --noinput 2>&1 || "
                "echo 'Warning: migrations failed, continuing anyway' && "
                "echo 'Collecting static files...' && python manage.py collectstatic --noinput 2>&1 || "
                "echo 'Warning: collectstatic failed, continuing anyway' && "
                "echo 'Starting server...' && "
            )

            try:
                if has_requirements:
                    with open(f"{proj_dir}/requirements.txt", 'r') as f:
                        requirements_text = f.read().lower()
            except Exception:
                requirements_text = ""

            # Procfile override if present
            try:
                procfile_path = os.path.join(proj_dir, 'Procfile')
                if os.path.exists(procfile_path):
                    with open(procfile_path, 'r') as pf:
                        for line in pf:
                            line = line.strip()
                            if line.startswith('web:'):
                                procfile_cmd = line.split('web:', 1)[1].strip()
                                break
                    if procfile_cmd:
                        log(f"📜 Using Procfile command: {procfile_cmd}")
            except Exception:
                procfile_cmd = None

            project_name = None
            if django_project:
                project_name = django_project.split('.')[0]

            if project_name and 'gunicorn' in requirements_text:
                default_django_start = (
                    f"gunicorn {project_name}.wsgi:application --bind 0.0.0.0:{port} "
                    "--workers 3 --timeout 120 --access-logfile - --error-logfile -"
                )
                log(f"🚀 Django command: {default_django_start}")
            else:
                default_django_start = procfile_cmd or f"python manage.py runserver 0.0.0.0:{port}"
                log(f"🚀 Django command: {default_django_start}")

        def command_to_json_array(command_str: str) -> str:
            parts = shlex.split(command_str)
            if not parts:
                return '[]'
            return '[' + ', '.join(json.dumps(part) for part in parts) + ']'

        if start_command:
            custom_command = start_command.strip()
            log(f"🚀 Using custom command: {custom_command}")
            if is_django and pre_start:
                full_cmd = f"{runtime_prefix}{pre_start}{custom_command}"
                escaped_cmd = full_cmd.replace('\\', '\\\\').replace('"', '\\"')
                cmd_json = f'["sh", "-c", "{escaped_cmd}"]'
            else:
                cmd_json = command_to_json_array(custom_command)
        elif is_django and default_django_start:
            full_cmd = f"{runtime_prefix}{pre_start}{default_django_start}"
            escaped_cmd = full_cmd.replace('\\', '\\\\').replace('"', '\\"')
            cmd_json = f'["sh", "-c", "{escaped_cmd}"]'
        else:
            try:
                if has_requirements:
                    with open(f"{proj_dir}/requirements.txt", 'r') as f:
                        req = f.read().lower()
                else:
                    req = ""
                if 'fastapi' in req or 'uvicorn' in req:
                    cmd_json = f'["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "{port}"]'
                elif 'gunicorn' in req and 'django' not in req:
                    app_name = entry_file.replace('.py', '')
                    cmd_json = f'["gunicorn", "--bind", "0.0.0.0:{port}", "{app_name}:app"]'
                else:
                    cmd_json = f'["python", "-m", "flask", "run", "--host=0.0.0.0", "--port={port}"]'
            except Exception:
                cmd_json = f'["python", "{entry_file}"]'

        log(f"🐍 Command: {cmd_json}")

        # Only add Django env if detected
        django_env = f"\nENV DJANGO_SETTINGS_MODULE={django_project}" if django_project else ""

        # If Django detected, create a local settings override to force DEBUG and ALLOWED_HOSTS, and persist data paths
        settings_override = ""
        make_data_dirs = ""
        if is_django and django_project:
            project_name_only = django_project.split('.')[0]
            # Create settings_local.py that properly handles DATABASE_URL and SQLite
            # We need to set DATABASE_URL before importing settings to avoid parsing errors
            settings_override = f"""
# Create local settings override for development inside container
RUN mkdir -p {project_name_only} && \
    cat > {project_name_only}/settings_local.py << 'PYEOF'
import os

# Set DATABASE_URL to SQLite if not already set (before importing settings)
if not os.environ.get('DATABASE_URL', '').strip():
    os.environ['DATABASE_URL'] = 'sqlite:////app/data/db.sqlite3'

# Now import settings (DATABASE_URL is set, so parsing won't fail)
try:
    from {project_name_only}.settings import *
except ImportError as e:
    # If settings import fails, try alternative import methods
    import sys
    import os
    # Add parent directory to path
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    # Try importing again
    try:
        from {project_name_only}.settings import *
    except ImportError:
        # Last resort: try direct import
        import importlib.util
        settings_path = os.path.join(current_dir, 'settings.py')
        if os.path.exists(settings_path):
            spec = importlib.util.spec_from_file_location('settings', settings_path)
            settings_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(settings_module)
            # Copy all attributes
            for attr in dir(settings_module):
                if not attr.startswith('_'):
                    globals()[attr] = getattr(settings_module, attr)
        else:
            raise ImportError(f"Cannot import {project_name_only}.settings")

# Respect DEBUG from environment, default to True for container deployment
DEBUG = os.environ.get('DEBUG', 'True').lower() in ('true', '1', 'yes')
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '*').split(',') if os.environ.get('ALLOWED_HOSTS') else ['*']

# Handle database configuration - override if needed
database_url = os.environ.get('DATABASE_URL', '').strip()
if database_url:
    if database_url.startswith('sqlite'):
        # SQLite from DATABASE_URL - handle both sqlite:/// and sqlite://// formats
        # sqlite://// means absolute path (4 slashes), sqlite:/// means relative (3 slashes)
        if database_url.startswith('sqlite:////'):
            # Absolute path: sqlite:////app/data/db.sqlite3 -> /app/data/db.sqlite3
            db_path = database_url.replace('sqlite:////', '/')
        elif database_url.startswith('sqlite:///'):
            # Relative path: sqlite:///db.sqlite3 -> db.sqlite3
            db_path = database_url.replace('sqlite:///', '')
        else:
            # Fallback
            db_path = database_url.replace('sqlite://', '')
        
        # Ensure directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        
        DATABASES = {{
            'default': {{
                'ENGINE': 'django.db.backends.sqlite3',
                'NAME': db_path,
            }}
        }}
    # If it's not SQLite, the parent settings should have handled it via dj_database_url
    # But we ensure it's valid
    elif not DATABASES.get('default'):
        # Fallback: try to parse with dj_database_url
        try:
            import dj_database_url
            DATABASES = {{
                'default': dj_database_url.parse(database_url, conn_max_age=600, ssl_require=False)
            }}
        except Exception:
            # If parsing fails, default to SQLite
            db_path = '/app/data/db.sqlite3'
            os.makedirs(os.path.dirname(db_path), exist_ok=True)
            DATABASES = {{
                'default': {{
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': db_path,
                }}
            }}
else:
    # No DATABASE_URL set - default to SQLite in persistent storage
    db_path = '/app/data/db.sqlite3'
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    DATABASES = {{
        'default': {{
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': db_path,
        }}
    }}

# Set static and media roots to persistent storage
STATIC_ROOT = '/app/data/staticfiles'
MEDIA_ROOT = '/app/data/media'

# Ensure static files are served (add whitenoise if available, otherwise use Django's static serving)
# Check if whitenoise is installed
try:
    import whitenoise
    # Add whitenoise middleware if not already present
    if 'whitenoise.middleware.WhiteNoiseMiddleware' not in MIDDLEWARE:
        # Insert after SecurityMiddleware if present, otherwise at the beginning
        try:
            security_index = MIDDLEWARE.index('django.middleware.security.SecurityMiddleware')
            MIDDLEWARE.insert(security_index + 1, 'whitenoise.middleware.WhiteNoiseMiddleware')
        except ValueError:
            MIDDLEWARE.insert(0, 'whitenoise.middleware.WhiteNoiseMiddleware')
    
    # Configure whitenoise
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'
except ImportError:
    # If whitenoise is not available, Django will serve static files in DEBUG mode
    # For production, ensure whitenoise is in requirements.txt
    pass

# Ensure SECRET_KEY is set from environment
if 'SECRET_KEY' in os.environ:
    SECRET_KEY = os.environ['SECRET_KEY']
elif not SECRET_KEY or SECRET_KEY == '':
    # Generate a secret key if not set
    try:
        from django.core.management.utils import get_random_secret_key
        SECRET_KEY = get_random_secret_key()
    except:
        # Fallback if Django utils not available
        import secrets
        SECRET_KEY = secrets.token_urlsafe(50)

# Ensure WSGI_APPLICATION is set if not already
try:
    if not WSGI_APPLICATION or WSGI_APPLICATION == '':
        WSGI_APPLICATION = '{project_name_only}.wsgi.application'
except NameError:
    WSGI_APPLICATION = '{project_name_only}.wsgi.application'
PYEOF
"""
            # Set default DJANGO_SETTINGS_MODULE in Dockerfile
            # Note: This can be overridden by user-provided environment variables at runtime
            django_env = f"\nENV DJANGO_SETTINGS_MODULE={project_name_only}.settings_local"
            make_data_dirs = "\nRUN mkdir -p /app/data/staticfiles /app/data/media || true"

        # Build-time Django setup is avoided; we run migrations/collectstatic at runtime
        django_setup = ""

        # Custom build command (optional)
        custom_build = ""
        if build_command and build_command.strip():
            # Split build command by && to handle multiple commands
            build_commands = [cmd.strip() for cmd in build_command.split('&&')]
            build_lines = " && \\\n    ".join(build_commands)
            custom_build = f'''
# Custom build command
RUN {build_lines}
'''
            log(f"✅ Added custom build command: {build_command}")

        # Determine if we need to install dependencies
        install_deps = ""
        if not build_command or 'pip install' not in build_command.lower():
            # Only auto-install if build command doesn't include pip install
            install_deps = '''
# Copy requirements first for better caching
COPY requirements.txt* Pipfile* ./
RUN if [ -f requirements.txt ]; then \\
    pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt; \\
elif [ -f Pipfile ]; then \\
    pip install --no-cache-dir --upgrade pip pipenv && pipenv install --deploy --system; \\
fi
'''
        else:
            install_deps = '''
# Copy requirements first for better caching
COPY requirements.txt* Pipfile* ./
'''

        dockerfile = f'''FROM python:3.11-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    python3-dev \
    libpq-dev \
    pkg-config \
  && rm -rf /var/lib/apt/lists/*
{install_deps}
# Copy application code
COPY . .
{custom_build}
{settings_override}{make_data_dirs}
EXPOSE {port}

ENV FLASK_APP={entry_file}
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT={port}
ENV PYTHONUNBUFFERED=1
ENV PORT={port}{django_env}

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', {port})); s.close()" || exit 1

CMD {cmd_json}
'''
        return dockerfile

    def _create_nodejs_dockerfile(self, proj_dir, entry_file, port, start_command, build_command, log):
        """Create optimized Node.js Dockerfile"""
        has_package_json = os.path.exists(f"{proj_dir}/package.json")

        # Determine start command
        if start_command:
            cmd_parts = start_command.split()
            cmd_json = '["' + '", "'.join(cmd_parts) + '"]'
        else:
            # Robust startup: load .env, try npm/yarn start, then fallback to node entry files
            runtime_prefix = "if [ -f .env ]; then export $(grep -v \"^#\" .env | xargs); fi; "
            fallback = (
                "if [ -f package.json ] && (npm run | grep -q ' start'); then npm start; "
                "elif command -v yarn >/dev/null 2>&1 && [ -f package.json ] && (yarn run | grep -q ' start'); then yarn start; "
                f"elif [ -f server.js ]; then node server.js; "
                f"elif [ -f app.js ]; then node app.js; "
                f"elif [ -f index.js ]; then node index.js; "
                f"else node {entry_file}; fi"
            )
            cmd_json = f'["sh", "-c", "{runtime_prefix}{fallback}"]'

        log(f"🚀 Start command: {cmd_json}")

        # Detect Node version
        node_version = '18'
        try:
            if has_package_json:
                with open(f"{proj_dir}/package.json", 'r') as f:
                    pkg_data = json.load(f)
                if 'engines' in pkg_data and 'node' in pkg_data['engines']:
                    node_req = pkg_data['engines']['node']
                    cleaned = node_req.replace('^', '').replace('~', '').replace('>=', '').replace('>', '').replace('=', '').strip()
                    match = re.search(r'(\d+)', cleaned)
                    if match:
                        required_version = int(match.group(1))
                        if required_version >= 20:
                            node_version = '20'
                        elif required_version >= 18:
                            node_version = '18'
                        else:
                            node_version = '16'
                log(f"📦 Using Node.js {node_version}")
        except:
            pass

        # Custom build command (optional)
        custom_build = ""
        if build_command and build_command.strip():
            # Split build command by && to handle multiple commands
            build_commands = [cmd.strip() for cmd in build_command.split('&&')]
            build_lines = " && \\\n    ".join(build_commands)
            custom_build = f'''
# Custom build command
RUN {build_lines}
'''
            log(f"✅ Added custom build command: {build_command}")
        else:
            # Default: install dependencies if no custom build command (supports yarn)
            custom_build = '''
# Install dependencies
RUN if [ -f yarn.lock ]; then \\
  (command -v yarn >/dev/null 2>&1 || npm i -g yarn) && yarn install --prod || yarn install; \\
elif [ -f package.json ]; then \\
  npm install --production --loglevel=error --ignore-scripts || \\
  npm install --loglevel=error --ignore-scripts; \\
fi
'''

        dockerfile = f'''FROM node:{node_version}-alpine
WORKDIR /app

# Copy application code first
COPY . .

# Install dependencies
{custom_build}

# Expose port
EXPOSE {port}

# Environment variables
ENV PORT={port}
ENV NODE_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:{port}', (r) => {{r.statusCode === 200 ? process.exit(0) : process.exit(1)}})" || exit 1

# Run application
CMD {cmd_json}
'''
        return dockerfile
    def _deploy_nodejs_dev(self, proj_dir, dep_id, port, config, log_callback):
        """Deploy Node.js app in development mode using npm run dev"""
        def log(message):
            if log_callback:
                log_callback(message)
            logger.info(message)

        try:
            log("🔥 Deploying in development mode...")

            # Check for package.json
            if not os.path.exists(f"{proj_dir}/package.json"):
                raise Exception("package.json not found for dev mode deployment")

            # Read package.json to check for dev script
            with open(f"{proj_dir}/package.json", 'r') as f:
                pkg_data = json.load(f)
            
            if 'scripts' not in pkg_data or 'dev' not in pkg_data['scripts']:
                raise Exception("No 'dev' script found in package.json")

            dev_command = pkg_data['scripts']['dev']
            log(f"📜 Dev script: {dev_command}")

            # Detect Node version
            node_version = '20'
            if 'engines' in pkg_data and 'node' in pkg_data['engines']:
                node_req = pkg_data['engines']['node']
                cleaned = node_req.replace('^', '').replace('~', '').replace('>=', '').replace('>', '').replace('=', '').strip()
                match = re.search(r'(\d+)', cleaned)
                if match:
                    required_version = int(match.group(1))
                    if required_version >= 20:
                        node_version = '20'
                    elif required_version >= 18:
                        node_version = '18'
                    else:
                        node_version = '16'
                log(f"📦 Node.js version: {node_version}")

            # Create development Dockerfile
            dockerfile = f'''FROM node:{node_version}
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install ALL dependencies (including devDependencies)
RUN npm install --loglevel=error || npm install --legacy-peer-deps --loglevel=error

# Copy source code
COPY . .

# Expose port
EXPOSE {port}

# Environment
ENV PORT={port}
ENV NODE_ENV=development

# Run dev server
CMD ["npm", "run", "dev"]
'''

            with open(f"{proj_dir}/Dockerfile", 'w') as f:
                f.write(dockerfile)

            # Build image
            log("🔨 Building development image...")
            try:
                img, logs = self.client.images.build(
                    path=proj_dir,
                    tag=f"dev-{dep_id}",
                    rm=True,
                    forcerm=True
                )
                
                for log_entry in logs:
                    if isinstance(log_entry, dict) and 'stream' in log_entry:
                        msg = log_entry['stream'].strip()
                        if msg:
                            log(msg)
                
                log("✅ Dev image built")
            except Exception as e:
                log(f"❌ Build failed: {str(e)}")
                raise

            # Run container
            log("🚀 Starting development server...")
            cont = self.client.containers.run(
                img.id,
                detach=True,
                ports={f'{port}/tcp': None},
                name=f"dev-{dep_id}",
                restart_policy={"Name": "unless-stopped"},
                environment={'PORT': port, 'NODE_ENV': 'development'},
                remove=False,
                labels={
                    'app': 'deployment-platform',
                    'type': 'web-service-dev',
                    'runtime': 'nodejs',
                    'deployment_id': dep_id
                }
            )

            # Wait and check status
            sleep(15)
            cont.reload()
            
            if cont.status != 'running':
                logs_text = cont.logs(tail=100)
                if isinstance(logs_text, bytes):
                    logs_text = logs_text.decode('utf-8', errors='ignore')
                log(f"❌ Dev server failed. Status: {cont.status}")
                for line in logs_text.split('\n'):
                    if line.strip():
                        log(line)
                cont.remove(force=True)
                raise Exception(f"Dev server exited: {cont.status}")

            mapped_port = cont.attrs['NetworkSettings']['Ports'][f'{port}/tcp'][0]['HostPort']
            log(f"✅ Dev server running!")
            log(f"🌐 Access at: http://localhost:{mapped_port}")
            log(f"🔥 Hot reload enabled")
            
            return cont.id, mapped_port

        except Exception as e:
            log(f"❌ Dev deployment failed: {str(e)}")
            raise

    def deploy_java_service(self, proj_dir, dep_id, config, log_callback=None):
        """Deploy Java application (Spring Boot/Maven/Gradle)"""
        def log(message):
            if log_callback:
                log_callback(message)
            logger.info(message)

        try:
            log("☕ Deploying Java service...")
            
            port = config.get('port', '8080')
            entry_jar = config.get('entryFile', 'app.jar')
            
            # Detect build tool
            has_maven = os.path.exists(f"{proj_dir}/pom.xml")
            has_gradle = os.path.exists(f"{proj_dir}/build.gradle") or os.path.exists(f"{proj_dir}/build.gradle.kts")
            
            if has_maven:
                log("📦 Detected Maven project")
                build_tool = 'maven'
            elif has_gradle:
                log("📦 Detected Gradle project")
                build_tool = 'gradle'
            else:
                log("⚠️ No build tool detected, expecting pre-built JAR")
                build_tool = 'jar'

            # Create Dockerfile based on build tool
            if build_tool == 'maven':
                dockerfile = f'''# Build stage
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /app

# Copy pom.xml and download dependencies
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests -B

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copy JAR from build stage
COPY --from=builder /app/target/*.jar app.jar

EXPOSE {port}

ENV JAVA_OPTS="-Xmx512m -Xms256m"
ENV SERVER_PORT={port}

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \\
  CMD wget --quiet --tries=1 --spider http://localhost:{port}/actuator/health || \\
      wget --quiet --tries=1 --spider http://localhost:{port}/ || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=$SERVER_PORT -jar app.jar"]
'''
            elif build_tool == 'gradle':
                dockerfile = f'''# Build stage
FROM gradle:8.5-jdk17 AS builder
WORKDIR /app

# Copy gradle files
COPY build.gradle* settings.gradle* gradlew ./
COPY gradle ./gradle

# Download dependencies
RUN gradle dependencies --no-daemon || true

# Copy source and build
COPY src ./src
RUN gradle bootJar --no-daemon -x test

# Runtime stage
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copy JAR from build stage
COPY --from=builder /app/build/libs/*.jar app.jar

EXPOSE {port}

ENV JAVA_OPTS="-Xmx512m -Xms256m"
ENV SERVER_PORT={port}

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \\
  CMD wget --quiet --tries=1 --spider http://localhost:{port}/actuator/health || \\
      wget --quiet --tries=1 --spider http://localhost:{port}/ || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=$SERVER_PORT -jar app.jar"]
'''
            else:
                # Pre-built JAR
                dockerfile = f'''FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

COPY {entry_jar} app.jar

EXPOSE {port}

ENV JAVA_OPTS="-Xmx512m -Xms256m"
ENV SERVER_PORT={port}

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \\
  CMD wget --quiet --tries=1 --spider http://localhost:{port}/ || exit 1

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -Dserver.port=$SERVER_PORT -jar app.jar"]
'''

            with open(f"{proj_dir}/Dockerfile", 'w') as f:
                f.write(dockerfile)

            # Build image
            log("🔨 Building Java application (this may take a few minutes)...")
            try:
                img, logs = self.client.images.build(
                    path=proj_dir,
                    tag=f"java-{dep_id}",
                    rm=True,
                    forcerm=True,
                    nocache=False
                )
                
                for log_entry in logs:
                    if isinstance(log_entry, dict) and 'stream' in log_entry:
                        msg = log_entry['stream'].strip()
                        if msg:
                            log(msg)
                
                log("✅ Java application built")
            except docker.errors.BuildError as e:
                log(f"❌ Build failed: {str(e)}")
                raise

            # Run container
            log("🚀 Starting Java service...")
            cont = self.client.containers.run(
                img.id,
                detach=True,
                ports={f'{port}/tcp': None},
                name=f"java-{dep_id}",
                restart_policy={"Name": "unless-stopped"},
                environment={
                    'SERVER_PORT': port,
                    'JAVA_OPTS': '-Xmx512m -Xms256m'
                },
                remove=False,
                labels={
                    'app': 'deployment-platform',
                    'type': 'web-service',
                    'runtime': 'java',
                    'deployment_id': dep_id
                }
            )

            # Wait for startup (Java apps take longer)
            log("⏳ Waiting for Java application to start (60 seconds)...")
            sleep(60)
            
            cont.reload()
            if cont.status != 'running':
                logs_text = cont.logs(tail=100)
                if isinstance(logs_text, bytes):
                    logs_text = logs_text.decode('utf-8', errors='ignore')
                log(f"❌ Java service failed. Status: {cont.status}")
                for line in logs_text.split('\n'):
                    if line.strip():
                        log(line)
                cont.remove(force=True)
                raise Exception(f"Java service exited: {cont.status}")

            mapped_port = cont.attrs['NetworkSettings']['Ports'][f'{port}/tcp'][0]['HostPort']
            
            # Show startup logs
            logs_text = cont.logs(tail=50)
            if isinstance(logs_text, bytes):
                logs_text = logs_text.decode('utf-8', errors='ignore')
            log("📋 Application logs:")
            for line in logs_text.split('\n')[-20:]:
                if line.strip():
                    log(line)
            
            log(f"✅ Java service deployed!")
            log(f"🌐 Access at: http://localhost:{mapped_port}")
            
            return cont.id, mapped_port

        except Exception as e:
            log(f"❌ Java deployment failed: {str(e)}")
            raise
    def stop_container(self, container_id):
        """Stop and remove a container"""
        try:
            logger.info(f"🛑 Stopping container {container_id}")
            container = self.client.containers.get(container_id)
            container.stop(timeout=10)
            logger.info(f"✅ Container {container_id} stopped")
            container.remove(force=True)
            logger.info(f"✅ Container {container_id} removed")
            return True
        except docker.errors.NotFound:
            logger.warning(f"⚠️ Container {container_id} not found")
            return False
        except Exception as e:
            logger.error(f"❌ Error stopping container {container_id}: {str(e)}")
            try:
                container = self.client.containers.get(container_id)
                container.remove(force=True)
                logger.info(f"✅ Container {container_id} force removed")
                return True
            except:
                logger.error(f"❌ Failed to force remove container {container_id}")
                return False

    def get_container_logs(self, container_id, tail=100):
        """Get logs from a container"""
        try:
            container = self.client.containers.get(container_id)
            logs = container.logs(tail=tail)
            if isinstance(logs, bytes):
                logs = logs.decode('utf-8', errors='ignore')
            return logs
        except docker.errors.NotFound:
            return f"Container {container_id} not found"
        except Exception as e:
            return f"Error getting logs: {str(e)}"

    def get_container_status(self, container_id):
        """Get container status"""
        try:
            container = self.client.containers.get(container_id)
            return container.status
        except docker.errors.NotFound:
            return "not_found"
        except Exception as e:
            logger.error(f"❌ Error getting container status: {str(e)}")
            return "error"

    def list_containers(self):
        """List all deployment containers"""
        try:
            containers = self.client.containers.list(all=True, filters={'label': 'app=deployment-platform'})
            deployment_containers = []
            for cont in containers:
                deployment_containers.append({
                    'id': cont.id,
                    'name': cont.name,
                    'status': cont.status,
                    'ports': cont.attrs.get('NetworkSettings', {}).get('Ports', {}),
                    'labels': cont.labels
                })
            return deployment_containers
        except Exception as e:
            logger.error(f"❌ Error listing containers: {str(e)}")
            return []

    def cleanup_stopped_containers(self):
        """Remove all stopped deployment containers"""
        try:
            containers = self.client.containers.list(
                all=True, 
                filters={
                    'status': 'exited',
                    'label': 'app=deployment-platform'
                }
            )
            removed = 0
            for cont in containers:
                try:
                    cont.remove(force=True)
                    logger.info(f"✅ Removed stopped container: {cont.name}")
                    removed += 1
                except:
                    pass
            return removed
        except Exception as e:
            logger.error(f"❌ Error cleaning up containers: {str(e)}")
            return 0

    def get_container_stats(self, container_id):
        """Get real-time container stats"""
        try:
            container = self.client.containers.get(container_id)
            stats = container.stats(stream=False)
            return stats
        except Exception as e:
            logger.error(f"❌ Error getting container stats: {str(e)}")
            return None
