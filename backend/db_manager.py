"""
Database Manager with PostgreSQL support and connection pooling
Supports both PostgreSQL (production) and SQLite (development)
"""
import os
import sqlite3
import logging
import threading
from contextlib import contextmanager
from typing import Optional, Dict, Any, List
import json
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import PostgreSQL
try:
    import psycopg2
    from psycopg2 import pool, sql
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False
    logger.warning("PostgreSQL not available, using SQLite")

class DatabaseManager:
    """Database manager with PostgreSQL and SQLite support"""
    
    def __init__(self):
        self.db_type = os.getenv('DATABASE_TYPE', 'sqlite').lower()
        self.connection_pool = None
        self._lock = threading.Lock()
        
        if self.db_type == 'postgresql' and POSTGRES_AVAILABLE:
            self._init_postgresql()
        else:
            self._init_sqlite()
        
        self.init_tables()
    
    def _init_postgresql(self):
        """Initialize PostgreSQL connection pool"""
        try:
            database_url = os.getenv('DATABASE_URL')
            if not database_url:
                logger.warning("DATABASE_URL not set, falling back to SQLite")
                self.db_type = 'sqlite'
                self._init_sqlite()
                return
            
            # Parse connection string
            min_conn = int(os.getenv('DB_POOL_MIN', 2))
            max_conn = int(os.getenv('DB_POOL_MAX', 10))
            
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                min_conn,
                max_conn,
                database_url,
                cursor_factory=RealDictCursor
            )
            
            logger.info(f"✅ PostgreSQL connection pool initialized ({min_conn}-{max_conn} connections)")
        except Exception as e:
            logger.error(f"❌ PostgreSQL initialization failed: {str(e)}, falling back to SQLite")
            self.db_type = 'sqlite'
            self._init_sqlite()
    
    def _init_sqlite(self):
        """Initialize SQLite database"""
        self.db_path = os.getenv('DATABASE_PATH', './db/deployments.db')
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        logger.info(f"✅ SQLite database initialized: {self.db_path}")
    
    @contextmanager
    def get_connection(self):
        """Get database connection (context manager)"""
        if self.db_type == 'postgresql' and self.connection_pool:
            conn = self.connection_pool.getconn()
            try:
                yield conn
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise
            finally:
                self.connection_pool.putconn(conn)
        else:
            # SQLite connection
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception as e:
                conn.rollback()
                raise
            finally:
                conn.close()
    
    def init_tables(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if self.db_type == 'postgresql':
                # PostgreSQL schema
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS deployments (
                        id VARCHAR(255) PRIMARY KEY,
                        project_name TEXT,
                        deployment_type TEXT,
                        status TEXT,
                        url TEXT,
                        direct_url TEXT,
                        timestamp TEXT,
                        container_id TEXT,
                        port INTEGER,
                        source TEXT,
                        repo TEXT,
                        branch TEXT,
                        config JSONB,
                        env_vars JSONB,
                        version INTEGER,
                        custom_domain TEXT,
                        volume_path TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS deployment_versions (
                        id SERIAL PRIMARY KEY,
                        deployment_id VARCHAR(255),
                        version INTEGER,
                        container_id TEXT,
                        timestamp TEXT,
                        config JSONB,
                        status TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS custom_domains (
                        id SERIAL PRIMARY KEY,
                        deployment_id VARCHAR(255),
                        domain VARCHAR(255) UNIQUE,
                        cloudflare_zone_id TEXT,
                        status TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
                    )
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS metrics (
                        id SERIAL PRIMARY KEY,
                        deployment_id VARCHAR(255),
                        timestamp TIMESTAMP,
                        cpu_percent REAL,
                        memory_mb REAL,
                        network_rx_mb REAL,
                        network_tx_mb REAL,
                        FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
                    )
                ''')
                
                # Create indexes for better performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_deployments_status ON deployments(status)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_deployments_container ON deployments(container_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_deployment ON metrics(deployment_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics(timestamp)')
                
            else:
                # SQLite schema (backward compatible)
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS deployments
                    (id TEXT PRIMARY KEY,
                     project_name TEXT,
                     deployment_type TEXT,
                     status TEXT,
                     url TEXT,
                     direct_url TEXT,
                     timestamp TEXT,
                     container_id TEXT,
                     port INTEGER,
                     source TEXT,
                     repo TEXT,
                     branch TEXT,
                     config TEXT,
                     env_vars TEXT,
                     version INTEGER,
                     custom_domain TEXT,
                     volume_path TEXT)
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS deployment_versions
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     deployment_id TEXT,
                     version INTEGER,
                     container_id TEXT,
                     timestamp TEXT,
                     config TEXT,
                     status TEXT,
                     FOREIGN KEY(deployment_id) REFERENCES deployments(id))
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS custom_domains
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     deployment_id TEXT,
                     domain TEXT UNIQUE,
                     cloudflare_zone_id TEXT,
                     status TEXT,
                     created_at TEXT,
                     FOREIGN KEY(deployment_id) REFERENCES deployments(id))
                ''')
                
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS metrics
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     deployment_id TEXT,
                     timestamp TEXT,
                     cpu_percent REAL,
                     memory_mb REAL,
                     network_rx_mb REAL,
                     network_tx_mb REAL,
                     FOREIGN KEY(deployment_id) REFERENCES deployments(id))
                ''')
            
            conn.commit()
            logger.info("✅ Database tables initialized")
    
    def save_deployment(self, deployment: Dict[str, Any]) -> bool:
        """Save or update deployment"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepare data
                config_json = json.dumps(deployment.get('config', {}))
                env_vars_json = json.dumps(deployment.get('environmentVariables', []))
                
                if self.db_type == 'postgresql':
                    cursor.execute('''
                        INSERT INTO deployments 
                        (id, project_name, deployment_type, status, url, direct_url, timestamp,
                         container_id, port, source, repo, branch, config, env_vars, version,
                         custom_domain, volume_path)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO UPDATE SET
                            status = EXCLUDED.status,
                            container_id = EXCLUDED.container_id,
                            port = EXCLUDED.port,
                            config = EXCLUDED.config,
                            env_vars = EXCLUDED.env_vars,
                            version = EXCLUDED.version,
                            updated_at = CURRENT_TIMESTAMP
                    ''', (
                        deployment['id'],
                        deployment.get('projectName'),
                        deployment.get('deploymentType'),
                        deployment.get('status'),
                        deployment.get('url'),
                        deployment.get('directUrl'),
                        deployment.get('timestamp'),
                        deployment.get('containerId'),
                        deployment.get('port'),
                        deployment.get('source'),
                        deployment.get('repo'),
                        deployment.get('branch'),
                        config_json,
                        env_vars_json,
                        deployment.get('version', 1),
                        deployment.get('customDomain'),
                        deployment.get('volumePath')
                    ))
                else:
                    cursor.execute('''
                        INSERT OR REPLACE INTO deployments
                        (id, project_name, deployment_type, status, url, direct_url, timestamp,
                         container_id, port, source, repo, branch, config, env_vars, version,
                         custom_domain, volume_path)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        deployment['id'],
                        deployment.get('projectName'),
                        deployment.get('deploymentType'),
                        deployment.get('status'),
                        deployment.get('url'),
                        deployment.get('directUrl'),
                        deployment.get('timestamp'),
                        deployment.get('containerId'),
                        deployment.get('port'),
                        deployment.get('source'),
                        deployment.get('repo'),
                        deployment.get('branch'),
                        config_json,
                        env_vars_json,
                        deployment.get('version', 1),
                        deployment.get('customDomain'),
                        deployment.get('volumePath')
                    ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"❌ Failed to save deployment: {str(e)}")
            return False
    
    def get_deployment(self, deployment_id: str) -> Optional[Dict[str, Any]]:
        """Get deployment by ID"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if self.db_type == 'postgresql':
                    cursor.execute('SELECT * FROM deployments WHERE id = %s', (deployment_id,))
                else:
                    cursor.execute('SELECT * FROM deployments WHERE id = ?', (deployment_id,))
                row = cursor.fetchone()
                
                if not row:
                    return None
                
                # Convert row to dict
                if self.db_type == 'postgresql':
                    deployment = dict(row)
                else:
                    deployment = {key: row[key] for key in row.keys()}
                
                # Parse JSON fields
                if deployment.get('config'):
                    deployment['config'] = json.loads(deployment['config']) if isinstance(deployment['config'], str) else deployment['config']
                if deployment.get('env_vars'):
                    deployment['env_vars'] = json.loads(deployment['env_vars']) if isinstance(deployment['env_vars'], str) else deployment['env_vars']
                
                # Convert to expected format
                return {
                    'id': deployment['id'],
                    'projectName': deployment.get('project_name'),
                    'deploymentType': deployment.get('deployment_type'),
                    'status': deployment.get('status'),
                    'url': deployment.get('url'),
                    'directUrl': deployment.get('direct_url'),
                    'timestamp': deployment.get('timestamp'),
                    'containerId': deployment.get('container_id'),
                    'port': deployment.get('port'),
                    'source': deployment.get('source'),
                    'repo': deployment.get('repo'),
                    'branch': deployment.get('branch'),
                    'config': deployment.get('config', {}),
                    'environmentVariables': deployment.get('env_vars', []),
                    'version': deployment.get('version', 1),
                    'customDomain': deployment.get('custom_domain'),
                    'volumePath': deployment.get('volume_path')
                }
        except Exception as e:
            logger.error(f"❌ Failed to get deployment: {str(e)}")
            return None
    
    def get_all_deployments(self) -> List[Dict[str, Any]]:
        """Get all deployments"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM deployments ORDER BY timestamp DESC')
                rows = cursor.fetchall()
                
                deployments = []
                for row in rows:
                    if self.db_type == 'postgresql':
                        deployment = dict(row)
                    else:
                        deployment = {key: row[key] for key in row.keys()}
                    
                    # Parse JSON fields
                    if deployment.get('config'):
                        deployment['config'] = json.loads(deployment['config']) if isinstance(deployment['config'], str) else deployment['config']
                    if deployment.get('env_vars'):
                        deployment['env_vars'] = json.loads(deployment['env_vars']) if isinstance(deployment['env_vars'], str) else deployment['env_vars']
                    
                    deployments.append({
                        'id': deployment['id'],
                        'projectName': deployment.get('project_name'),
                        'deploymentType': deployment.get('deployment_type'),
                        'status': deployment.get('status'),
                        'url': deployment.get('url'),
                        'directUrl': deployment.get('direct_url'),
                        'timestamp': deployment.get('timestamp'),
                        'containerId': deployment.get('container_id'),
                        'port': deployment.get('port'),
                        'source': deployment.get('source'),
                        'repo': deployment.get('repo'),
                        'branch': deployment.get('branch'),
                        'config': deployment.get('config', {}),
                        'environmentVariables': deployment.get('env_vars', []),
                        'version': deployment.get('version', 1),
                        'customDomain': deployment.get('custom_domain'),
                        'volumePath': deployment.get('volume_path')
                    })
                
                return deployments
        except Exception as e:
            logger.error(f"❌ Failed to get deployments: {str(e)}")
            return []
    
    def delete_deployment(self, deployment_id: str) -> bool:
        """Delete deployment"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if self.db_type == 'postgresql':
                    cursor.execute('DELETE FROM deployments WHERE id = %s', (deployment_id,))
                else:
                    cursor.execute('DELETE FROM deployments WHERE id = ?', (deployment_id,))
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"❌ Failed to delete deployment: {str(e)}")
            return False
    
    def save_deployment_version(self, deployment_id: str, version: Dict[str, Any]) -> bool:
        """Save deployment version"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                config_json = json.dumps(version.get('config', {}))
                
                if self.db_type == 'postgresql':
                    cursor.execute('''
                        INSERT INTO deployment_versions
                        (deployment_id, version, container_id, timestamp, config, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (
                        deployment_id,
                        version.get('version'),
                        version.get('containerId'),
                        version.get('timestamp'),
                        config_json,
                        version.get('status', 'previous')
                    ))
                else:
                    cursor.execute('''
                        INSERT INTO deployment_versions
                        (deployment_id, version, container_id, timestamp, config, status)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (
                        deployment_id,
                        version.get('version'),
                        version.get('containerId'),
                        version.get('timestamp'),
                        config_json,
                        version.get('status', 'previous')
                    ))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"❌ Failed to save version: {str(e)}")
            return False
    
    def get_deployment_versions(self, deployment_id: str) -> List[Dict[str, Any]]:
        """Get deployment versions"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                if self.db_type == 'postgresql':
                    cursor.execute('SELECT * FROM deployment_versions WHERE deployment_id = %s ORDER BY version DESC', (deployment_id,))
                else:
                    cursor.execute('SELECT * FROM deployment_versions WHERE deployment_id = ? ORDER BY version DESC', (deployment_id,))
                rows = cursor.fetchall()
                
                versions = []
                for row in rows:
                    if self.db_type == 'postgresql':
                        version = dict(row)
                    else:
                        version = {key: row[key] for key in row.keys()}
                    
                    if version.get('config'):
                        version['config'] = json.loads(version['config']) if isinstance(version['config'], str) else version['config']
                    
                    versions.append({
                        'version': version.get('version'),
                        'containerId': version.get('container_id'),
                        'timestamp': version.get('timestamp'),
                        'config': version.get('config', {}),
                        'status': version.get('status')
                    })
                
                return versions
        except Exception as e:
            logger.error(f"❌ Failed to get versions: {str(e)}")
            return []
    
    def save_metrics(self, deployment_id: str, stats: Dict[str, Any]) -> bool:
        """Save deployment metrics"""
        try:
            cpu_stats = stats.get('cpu_stats', {})
            cpu_usage = cpu_stats.get('cpu_usage', {})
            system_cpu = cpu_stats.get('system_cpu_usage', 1)
            
            cpu_percent = 0
            if system_cpu > 0:
                cpu_percent = (cpu_usage.get('total_usage', 0) / system_cpu) * 100
            
            memory_mb = stats.get('memory_stats', {}).get('usage', 0) / 1024 / 1024
            network = stats.get('networks', {}).get('eth0', {})
            network_rx_mb = network.get('rx_bytes', 0) / 1024 / 1024
            network_tx_mb = network.get('tx_bytes', 0) / 1024 / 1024
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                timestamp = datetime.now().isoformat()
                
                if self.db_type == 'postgresql':
                    cursor.execute('''
                        INSERT INTO metrics
                        (deployment_id, timestamp, cpu_percent, memory_mb, network_rx_mb, network_tx_mb)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ''', (deployment_id, timestamp, cpu_percent, memory_mb, network_rx_mb, network_tx_mb))
                else:
                    cursor.execute('''
                        INSERT INTO metrics
                        (deployment_id, timestamp, cpu_percent, memory_mb, network_rx_mb, network_tx_mb)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (deployment_id, timestamp, cpu_percent, memory_mb, network_rx_mb, network_tx_mb))
                
                conn.commit()
                return True
        except Exception as e:
            logger.error(f"❌ Failed to save metrics: {str(e)}")
            return False
    
    def get_metrics(self, deployment_id: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Get deployment metrics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                if self.db_type == 'postgresql':
                    # Use proper PostgreSQL interval syntax
                    cursor.execute('''
                        SELECT timestamp, cpu_percent, memory_mb, network_rx_mb, network_tx_mb
                        FROM metrics
                        WHERE deployment_id = %s
                        AND timestamp >= NOW() - INTERVAL '1 hour' * %s
                        ORDER BY timestamp DESC
                        LIMIT %s
                    ''', (deployment_id, hours, hours * 60))
                else:
                    cursor.execute('''
                        SELECT timestamp, cpu_percent, memory_mb, network_rx_mb, network_tx_mb
                        FROM metrics
                        WHERE deployment_id = ?
                        ORDER BY timestamp DESC
                        LIMIT ?
                    ''', (deployment_id, hours * 60))
                
                rows = cursor.fetchall()
                
                metrics = []
                for row in rows:
                    if self.db_type == 'postgresql':
                        metric = dict(row)
                    else:
                        metric = {key: row[key] for key in row.keys()}
                    
                    metrics.append({
                        'timestamp': str(metric['timestamp']),
                        'cpu': metric.get('cpu_percent', 0),
                        'memory': metric.get('memory_mb', 0),
                        'networkRx': metric.get('network_rx_mb', 0),
                        'networkTx': metric.get('network_tx_mb', 0)
                    })
                
                return metrics
        except Exception as e:
            logger.error(f"❌ Failed to get metrics: {str(e)}")
            return []
    
    def close(self):
        """Close database connections"""
        if self.connection_pool:
            self.connection_pool.closeall()
            logger.info("✅ PostgreSQL connection pool closed")

