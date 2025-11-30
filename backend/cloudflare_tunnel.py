import subprocess
import threading
import re
import time
import logging
import os
import signal

logger = logging.getLogger(__name__)

class CloudflareTunnelManager:
    """
    Manages Cloudflare Quick Tunnels for automatic public URL generation
    Just like Render.com - each deployment gets a public URL!
    """
    
    def __init__(self):
        self.active_tunnels = {}  # {deployment_id: {process, url, port}}
        self.tunnel_lock = threading.Lock()
        logger.info("✅ Cloudflare Tunnel Manager initialized")
    
    def _check_cloudflared_installed(self):
        """Check if cloudflared is installed"""
        try:
            result = subprocess.run(
                ['cloudflared', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"✅ cloudflared found: {result.stdout.strip()}")
                return True
            return False
        except FileNotFoundError:
            logger.error("❌ cloudflared not installed!")
            return False
        except Exception as e:
            logger.error(f"❌ Error checking cloudflared: {str(e)}")
            return False
    
    def create_tunnel(self, deployment_id, local_port, log_callback=None):
        """
        Create a Cloudflare Quick Tunnel for the deployment
        Returns: Public URL (e.g., https://random-name.trycloudflare.com)
        """
        def log(message):
            if log_callback:
                log_callback(message)
            logger.info(message)
        
        try:
            # Check if cloudflared is installed
            if not self._check_cloudflared_installed():
                log("⚠️ cloudflared not installed - using localhost URL")
                log("📝 Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
                return f"http://localhost:{local_port}"
            
            log(f"🌐 Creating Cloudflare Tunnel for port {local_port}...")
            log("⏳ Generating public URL (this takes ~10 seconds)...")
            
            # Start cloudflared tunnel process
            process = subprocess.Popen(
                ['cloudflared', 'tunnel', '--url', f'http://localhost:{local_port}'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )
            
            # Wait for tunnel URL to be generated
            public_url = None
            timeout = 30  # 30 second timeout
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                line = process.stderr.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                # Log cloudflared output
                log(f"[cloudflared] {line.strip()}")
                
                # Extract the public URL from cloudflared output
                url_match = re.search(r'https://[a-zA-Z0-9-]+\.trycloudflare\.com', line)
                if url_match:
                    public_url = url_match.group(0)
                    break
                
                # Check if process died
                if process.poll() is not None:
                    stderr = process.stderr.read()
                    log(f"❌ cloudflared process died: {stderr}")
                    return f"http://localhost:{local_port}"
            
            if not public_url:
                log("⚠️ Could not extract public URL from cloudflared - using localhost")
                process.terminate()
                return f"http://localhost:{local_port}"
            
            # Store tunnel info
            with self.tunnel_lock:
                self.active_tunnels[deployment_id] = {
                    'process': process,
                    'url': public_url,
                    'port': local_port,
                    'created_at': time.time()
                }
            
            log(f"✅ Cloudflare Tunnel created!")
            log(f"🌍 Public URL: {public_url}")
            log(f"🔒 Secure HTTPS tunnel active")
            log(f"📱 Share this URL with anyone!")
            
            return public_url
            
        except FileNotFoundError:
            log("⚠️ cloudflared not found - install it for public URLs")
            log("📝 Install: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/")
            return f"http://localhost:{local_port}"
        except Exception as e:
            log(f"❌ Error creating tunnel: {str(e)}")
            return f"http://localhost:{local_port}"
    
    def stop_tunnel(self, deployment_id):
        """Stop and remove a Cloudflare tunnel"""
        try:
            with self.tunnel_lock:
                if deployment_id in self.active_tunnels:
                    tunnel_info = self.active_tunnels[deployment_id]
                    process = tunnel_info['process']
                    url = tunnel_info['url']
                    
                    logger.info(f"🛑 Stopping tunnel for {deployment_id}: {url}")
                    
                    # Terminate cloudflared process
                    try:
                        process.terminate()
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                    
                    del self.active_tunnels[deployment_id]
                    logger.info(f"✅ Tunnel stopped for {deployment_id}")
                    return True
                else:
                    logger.warning(f"⚠️ No tunnel found for {deployment_id}")
                    return False
        except Exception as e:
            logger.error(f"❌ Error stopping tunnel for {deployment_id}: {str(e)}")
            return False
    
    def get_tunnel_info(self, deployment_id):
        """Get tunnel information for a deployment"""
        with self.tunnel_lock:
            return self.active_tunnels.get(deployment_id)
    
    def get_all_tunnels(self):
        """Get all active tunnels"""
        with self.tunnel_lock:
            return dict(self.active_tunnels)
    
    def cleanup_all(self):
        """Stop all active tunnels (call on shutdown)"""
        logger.info("🧹 Cleaning up all Cloudflare tunnels...")
        with self.tunnel_lock:
            for deployment_id in list(self.active_tunnels.keys()):
                self.stop_tunnel(deployment_id)
        logger.info("✅ All tunnels cleaned up")
