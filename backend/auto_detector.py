import os
import json
import re
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

class ProjectDetector:
    """
    Auto-detect project type, runtime, build commands, and configuration
    Just like Render.com's smart detection!
    """
    
    def __init__(self, project_dir):
        self.project_dir = Path(project_dir)
        self.files = self._scan_directory()
    
    def _scan_directory(self):
        """Scan directory for key files"""
        files = {}
        common_files = [
            'package.json', 'requirements.txt', 'pom.xml', 'build.gradle',
            'Gemfile', 'go.mod', 'Cargo.toml', 'composer.json',
            'index.html', 'index.js', 'app.py', 'main.py', 'server.js',
            'next.config.js', 'vite.config.js', 'vue.config.js',
            'angular.json', 'gatsby-config.js', 'nuxt.config.js',
            'manage.py', 'wsgi.py'
        ]
        
        for file in common_files:
            file_path = self.project_dir / file
            if file_path.exists():
                files[file] = file_path
        
        # Also look for any wsgi.py in subdirectories for Django
        for path in self.project_dir.rglob('wsgi.py'):
            files['wsgi.py'] = path
            break
            
        return files
    
    def detect_all(self):
        """
        Master detection function - returns complete deployment configuration
        """
        logger.info("🔍 Starting intelligent project detection...")
        
        detection = self._detect_project_type()
        detection['framework'] = self._detect_framework(detection)
        detection['config'] = self._generate_config(detection)
        
        logger.info(f"✅ Detected: {detection['framework']} ({detection['runtime']})")
        
        return detection
    
    def _detect_project_type(self):
        """Detect if project is static site or web service"""
        
        # Check for Python web frameworks
        if 'requirements.txt' in self.files:
            requirements = self.files['requirements.txt'].read_text().lower()
            if any(fw in requirements for fw in ['django', 'flask', 'fastapi', 'uvicorn', 'starlette']):
                return {'type': 'service', 'runtime': 'python'}
        
        # Check for Python files
        if 'app.py' in self.files or 'main.py' in self.files or 'manage.py' in self.files:
            return {'type': 'service', 'runtime': 'python'}
        
        # Check for Java
        if 'pom.xml' in self.files:
            return {'type': 'service', 'runtime': 'java', 'buildTool': 'maven'}
        if 'build.gradle' in self.files:
            return {'type': 'service', 'runtime': 'java', 'buildTool': 'gradle'}
        
        # Check for Node.js
        if 'package.json' in self.files:
            pkg_data = json.loads(self.files['package.json'].read_text())
            scripts = pkg_data.get('scripts', {})
            dependencies = {**pkg_data.get('dependencies', {}), **pkg_data.get('devDependencies', {})}
            
            if any(dep in dependencies for dep in ['vite', 'next', 'gatsby', 'vue', 'react', 'angular', 'svelte']):
                if 'build' in scripts:
                    return {'type': 'static', 'runtime': 'nodejs'}
            
            if any(dep in dependencies for dep in ['express', 'koa', 'fastify', 'hapi', 'nestjs']):
                return {'type': 'service', 'runtime': 'nodejs'}
            
            if 'server.js' in self.files or 'index.js' in self.files:
                return {'type': 'service', 'runtime': 'nodejs'}
            
            if 'build' in scripts:
                return {'type': 'static', 'runtime': 'nodejs'}
        
        if 'index.html' in self.files:
            return {'type': 'static', 'runtime': 'static'}
        
        return {'type': 'static', 'runtime': 'static'}
    
    def _detect_framework(self, detection):
        runtime = detection['runtime']
        
        if runtime == 'python':
            return self._detect_python_framework()
        elif runtime == 'nodejs':
            return self._detect_nodejs_framework()
        elif runtime == 'java':
            return self._detect_java_framework()
        else:
            return 'html'
    
    def _detect_python_framework(self):
        if 'manage.py' in self.files:
            return 'django'
            
        if 'requirements.txt' not in self.files:
            return 'python'
        
        requirements = self.files['requirements.txt'].read_text().lower()
        
        if 'django' in requirements:
            return 'django'
        elif 'fastapi' in requirements:
            return 'fastapi'
        elif 'flask' in requirements:
            return 'flask'
        
        return 'python'
    
    def _detect_nodejs_framework(self):
        if 'package.json' not in self.files:
            return 'nodejs'
        
        pkg_data = json.loads(self.files['package.json'].read_text())
        dependencies = {**pkg_data.get('dependencies', {}), **pkg_data.get('devDependencies', {})}
        
        if 'next' in dependencies: return 'nextjs'
        if 'vite' in dependencies: return 'react-vite'
        if 'vue' in dependencies: return 'vue'
        if 'express' in dependencies: return 'express'
        
        return 'nodejs'
    
    def _detect_java_framework(self):
        if 'pom.xml' in self.files: return 'maven'
        if 'build.gradle' in self.files: return 'gradle'
        return 'java'
    
    def _generate_config(self, detection):
        proj_type = detection['type']
        runtime = detection['runtime']
        framework = detection['framework']
        
        if proj_type == 'static':
            return self._generate_static_config(framework)
        else:
            return self._generate_service_config(runtime, framework)
    
    def _generate_static_config(self, framework):
        configs = {
            'react-vite': {'buildCommand': 'npm install && npm run build', 'publishDir': 'dist'},
            'nextjs': {'buildCommand': 'npm install && npm run build && npm run export', 'publishDir': 'out'},
            'html': {'buildCommand': 'echo "No build needed"', 'publishDir': '.'}
        }
        return configs.get(framework, {'buildCommand': 'npm install && npm run build', 'publishDir': 'dist'})
    
    def _generate_service_config(self, runtime, framework):
        if runtime == 'python':
            return self._generate_python_config(framework)
        elif runtime == 'nodejs':
            return self._generate_nodejs_config(framework)
        return {}
    
    def _generate_python_config(self, framework):
        config = {
            'runtime': 'python',
            'entryFile': 'app.py',
            'port': '5000',
            'startCommand': ''
        }
        
        # Check requirements for Gunicorn
        has_gunicorn = False
        if 'requirements.txt' in self.files:
            reqs = self.files['requirements.txt'].read_text().lower()
            has_gunicorn = 'gunicorn' in reqs

        if framework == 'django':
            config['port'] = '8000'
            config['entryFile'] = 'manage.py'
            
            # Smart Django Start Command Detection
            if has_gunicorn:
                project_name = None
                # Method 1: Look for wsgi.py parent folder
                if 'wsgi.py' in self.files:
                    # Parent folder of wsgi.py is usually the project name
                    project_name = self.files['wsgi.py'].parent.name
                
                # Method 2: Check manage.py for DJANGO_SETTINGS_MODULE
                if not project_name and 'manage.py' in self.files:
                    try:
                        content = self.files['manage.py'].read_text()
                        match = re.search(r'["\']DJANGO_SETTINGS_MODULE["\']\s*,\s*["\']([^"\']+)["\']', content)
                        if match:
                            project_name = match.group(1).split('.')[0]
                    except:
                        pass

                if project_name:
                    config['startCommand'] = f"gunicorn {project_name}.wsgi:application --bind 0.0.0.0:8000"
                else:
                    # Fallback if we can't find project name
                    config['startCommand'] = "gunicorn <project_name>.wsgi:application --bind 0.0.0.0:8000"
            else:
                # Fallback to runserver if no gunicorn
                config['startCommand'] = "python manage.py runserver 0.0.0.0:8000"

        elif framework == 'flask':
            config['port'] = '5000'
            if has_gunicorn:
                config['startCommand'] = "gunicorn app:app --bind 0.0.0.0:5000"
            else:
                config['startCommand'] = "python app.py"

        return config
    
    def _generate_nodejs_config(self, framework):
        config = {
            'runtime': 'nodejs',
            'entryFile': 'index.js',
            'port': '3000',
            'startCommand': 'node index.js'
        }
        
        if 'package.json' in self.files:
            pkg = json.loads(self.files['package.json'].read_text())
            if pkg.get('scripts', {}).get('start'):
                config['startCommand'] = 'npm start'
                
        return config

    def get_smart_suggestions(self):
        detection = self.detect_all()
        suggestions = {
            'detected': f"{detection['framework']} application",
            'deploymentType': 'Static Site' if detection['type'] == 'static' else 'Web Service',
            'runtime': detection['runtime'].title(),
            'recommendations': []
        }
        
        conf = detection['config']
        if detection['type'] == 'static':
            suggestions['recommendations'].append(f"Build: {conf['buildCommand']}")
            suggestions['recommendations'].append(f"Publish: {conf['publishDir']}")
        else:
            suggestions['recommendations'].append(f"Start: {conf['startCommand']}")
            suggestions['recommendations'].append(f"Port: {conf['port']}")
            
        return suggestions