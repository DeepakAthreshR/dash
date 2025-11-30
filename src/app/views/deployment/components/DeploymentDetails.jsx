import { useState, useEffect } from 'react';
import MetricsDashboard from './MetricsDashboard';
import CustomDomainManager from './CustomDomainManager';
import RollbackManager from './RollbackManager';

// ✅ Sidebar awareness imports
import useSettings from "app/hooks/useSettings";
import { sideNavWidth, sidenavCompactWidth } from "app/utils/constant";

function DeploymentDetails({ deploymentId, onClose }) {
  const [deployment, setDeployment] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [logs, setLogs] = useState('');
  const [loading, setLoading] = useState(true);

  // ✅ Sidebar Offset Calculation
  const { settings } = useSettings();
  const sidebarMode = settings.layout1Settings.leftSidebar.mode;
  const showSidebar = settings.layout1Settings.leftSidebar.show;

  const getLeftOffset = () => {
    if (!showSidebar) return 0;
    if (sidebarMode === 'full') return sideNavWidth;
    if (sidebarMode === 'compact') return sidenavCompactWidth;
    return 0; // mobile or close
  };

  const leftOffset = getLeftOffset();

  useEffect(() => {
    fetchDeployment();
  }, [deploymentId]);

  const fetchDeployment = async () => {
    try {
      const response = await fetch(`/api/deployments/${deploymentId}`);
      const data = await response.json();
      setDeployment(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch deployment:', error);
      setLoading(false);
    }
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch(`/api/deployments/${deploymentId}/logs?tail=200`);
      const data = await response.json();
      setLogs(data.logs);
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    }
  };

  const handleRestart = async () => {
    if (!confirm('Restart this deployment?')) return;
    try {
      const response = await fetch(`/api/deployments/${deploymentId}/restart`, { method: 'POST' });
      if (response.ok) {
        alert('✅ Deployment restarted successfully!');
        fetchDeployment();
      } else {
        alert('❌ Failed to restart deployment');
      }
    } catch (error) {
      alert(`❌ Restart failed: ${error.message}`);
    }
  };

  const handleDelete = async () => {
    if (!confirm('⚠️ Delete this deployment? This cannot be undone!')) return;
    try {
      const response = await fetch(`/api/deployments/${deploymentId}`, { method: 'DELETE' });
      if (response.ok) {
        alert('✅ Deployment deleted successfully');
        onClose();
        window.location.reload();
      } else {
        alert('❌ Failed to delete deployment');
      }
    } catch (error) {
      alert(`❌ Delete failed: ${error.message}`);
    }
  };

  // Dynamic style for sidebar awareness
  const overlayStyle = {
    ...styles.modalOverlay,
    left: leftOffset,
    width: `calc(100% - ${leftOffset}px)`
  };

  if (loading) {
    return (
      <div style={overlayStyle}>
        <div style={styles.modalContent}>
          <div style={styles.loading}>Loading deployment details...</div>
        </div>
      </div>
    );
  }

  if (!deployment) {
    return (
      <div style={overlayStyle}>
        <div style={styles.modalContent}>
          <div style={styles.error}>Deployment not found</div>
          <button onClick={onClose} style={styles.closeButton}>Close</button>
        </div>
      </div>
    );
  }

  // ✅ Helper to safely get config values (handling both root and nested config)
  const getConfigValue = (key, fallback) => {
    // Check root level first, then config object
    if (deployment[key] !== undefined) return deployment[key];
    if (deployment.config && deployment.config[key] !== undefined) return deployment.config[key];
    return fallback;
  };

  const autoRestart = getConfigValue('autoRestart', true); // Default to true if not found
  const healthCheckPath = getConfigValue('healthCheckPath', '/');

  return (
    <div style={overlayStyle} onClick={onClose}>
      <div style={styles.modalContent} onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div style={styles.header}>
          <div>
            <h2 style={styles.title}>📦 {deployment.projectName}</h2>
            <div style={styles.subtitle}>
              <span style={{...styles.badge, ...styles[`badge_${deployment.status}`]}}>
                {deployment.status}
              </span>
              <span style={styles.subInfo}>Version {deployment.version}</span>
              <span style={styles.subInfo}>{deployment.deploymentType}</span>
            </div>
          </div>
          <button onClick={onClose} style={styles.closeBtn}>×</button>
        </div>

        {/* Tabs */}
        <div style={styles.tabs}>
          {['overview', 'logs', 'metrics', 'versions', 'domains', 'settings'].map(tab => (
            <button
              key={tab}
              onClick={() => {
                setActiveTab(tab);
                if (tab === 'logs') fetchLogs();
              }}
              style={{
                ...styles.tab,
                ...(activeTab === tab ? styles.tabActive : {})
              }}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div style={styles.tabContent}>
          {activeTab === 'overview' && (
            <div>
              <div style={styles.infoGrid}>
                <div style={styles.infoCard}>
                  <div style={styles.infoLabel}>Deployment ID</div>
                  <div style={styles.infoValue}>{deployment.id}</div>
                </div>
                <div style={styles.infoCard}>
                  <div style={styles.infoLabel}>Type</div>
                  <div style={styles.infoValue}>{deployment.deploymentType}</div>
                </div>
                <div style={styles.infoCard}>
                  <div style={styles.infoLabel}>Port</div>
                  <div style={styles.infoValue}>{deployment.port}</div>
                </div>
                <div style={styles.infoCard}>
                  <div style={styles.infoLabel}>Source</div>
                  <div style={styles.infoValue}>{deployment.source}</div>
                </div>
                <div style={styles.infoCard}>
                  <div style={styles.infoLabel}>Created</div>
                  <div style={styles.infoValue}>
                    {new Date(deployment.timestamp).toLocaleDateString()}
                  </div>
                </div>
                {deployment.volumePath && (
                  <div style={styles.infoCard}>
                    <div style={styles.infoLabel}>💾 Persistent Volume</div>
                    <div style={styles.infoValue}>Enabled</div>
                  </div>
                )}
              </div>

              <div style={styles.actions}>
                <a 
                  href={deployment.directUrl || deployment.url || `http://localhost:${deployment.port}`} 
                  target="_blank" 
                  rel="noopener noreferrer"
                  style={styles.actionBtn}
                >
                  🌐 Visit Site {deployment.port ? `(Port ${deployment.port})` : ''}
                </a>
                <button onClick={handleRestart} style={{...styles.actionBtn, ...styles.actionBtnWarning}}>
                  🔄 Restart
                </button>
                <button onClick={handleDelete} style={{...styles.actionBtn, ...styles.actionBtnDanger}}>
                  🗑️ Delete
                </button>
              </div>

              {deployment.environmentVariables?.length > 0 && (
                <div style={styles.section}>
                  <h3 style={styles.sectionTitle}>🔐 Environment Variables</h3>
                  <div style={styles.envVars}>
                    {deployment.environmentVariables.map((env, i) => (
                      <div key={i} style={styles.envVar}>
                        <code style={styles.envKey}>{env.key}</code>
                        <span style={styles.envValue}>
                          {env.isSecret ? '••••••••' : env.value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {deployment.repo && (
                <div style={styles.section}>
                  <h3 style={styles.sectionTitle}>📂 Repository</h3>
                  <div style={styles.repoInfo}>
                    <div><strong>URL:</strong> {deployment.repo}</div>
                    <div><strong>Branch:</strong> {deployment.branch}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'logs' && (
            <div>
              <div style={styles.logsHeader}>
                <h3 style={styles.sectionTitle}>📋 Container Logs</h3>
                <button onClick={fetchLogs} style={styles.refreshBtn}>
                  🔄 Refresh
                </button>
              </div>
              <pre style={styles.logs}>{logs || 'Loading logs...'}</pre>
            </div>
          )}

          {activeTab === 'metrics' && (
            <MetricsDashboard deploymentId={deploymentId} />
          )}

          {activeTab === 'versions' && (
            <RollbackManager 
              deploymentId={deploymentId} 
              versions={deployment.versions || []}
              onRollback={fetchDeployment}
            />
          )}

          {activeTab === 'domains' && (
            <CustomDomainManager 
              deploymentId={deploymentId}
              currentDomain={deployment.customDomain}
              onUpdate={fetchDeployment}
            />
          )}

          {activeTab === 'settings' && (
            <div style={styles.section}>
              <h3 style={styles.sectionTitle}>⚙️ Settings</h3>
              <div style={styles.settings}>
                <div style={styles.settingRow}>
                  <div>
                    <div style={styles.settingLabel}>Auto-Restart</div>
                    <div style={styles.settingDesc}>
                      Automatically restart on failure
                    </div>
                  </div>
                  <div style={styles.settingValue}>
                    {/* ✅ FIX: Correctly check value using helper */}
                    {autoRestart ? '✅ Enabled' : '❌ Disabled'}
                  </div>
                </div>
                <div style={styles.settingRow}>
                  <div>
                    <div style={styles.settingLabel}>Health Check Path</div>
                    <div style={styles.settingDesc}>
                      Path used for health monitoring
                    </div>
                  </div>
                  <div style={styles.settingValue}>
                    {/* ✅ FIX: Correctly check value using helper */}
                    <code>{healthCheckPath}</code>
                  </div>
                </div>
                <div style={styles.settingRow}>
                  <div>
                    <div style={styles.settingLabel}>Container ID</div>
                    <div style={styles.settingDesc}>
                      Docker container identifier
                    </div>
                  </div>
                  <div style={styles.settingValue}>
                    <code>{deployment.containerId.substring(0, 12)}</code>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const styles = {
  modalOverlay: {
    position: 'fixed',
    top: 0,
    bottom: 0,
    background: 'rgba(0, 0, 0, 0.7)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    zIndex: 1200,
    padding: '20px',
    transition: 'left 0.3s ease, width 0.3s ease',
  },
  modalContent: {
    background: 'white',
    width: '100%',
    maxWidth: '1200px',
    maxHeight: '90vh',
    borderRadius: '12px',
    overflow: 'hidden',
    display: 'flex',
    flexDirection: 'column',
    boxShadow: '0 20px 60px rgba(0,0,0,0.3)',
  },
  loading: {
    padding: '60px',
    textAlign: 'center',
    fontSize: '18px',
    color: '#666',
  },
  error: {
    padding: '40px',
    textAlign: 'center',
    color: '#ff4444',
    fontSize: '16px',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    padding: '30px',
    borderBottom: '1px solid #e0e0e0',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
  },
  title: {
    margin: '0 0 10px 0',
    fontSize: '28px',
    fontWeight: '600',
  },
  subtitle: {
    display: 'flex',
    gap: '15px',
    alignItems: 'center',
  },
  badge: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: '600',
    textTransform: 'uppercase',
  },
  badge_active: {
    background: '#4caf50',
  },
  badge_stopped: {
    background: '#ff9800',
  },
  subInfo: {
    opacity: 0.9,
    fontSize: '14px',
  },
  closeBtn: {
    background: 'rgba(255,255,255,0.2)',
    border: 'none',
    color: 'white',
    fontSize: '32px',
    cursor: 'pointer',
    width: '40px',
    height: '40px',
    borderRadius: '50%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    lineHeight: '1',
  },
  tabs: {
    display: 'flex',
    borderBottom: '1px solid #e0e0e0',
    background: '#f5f5f5',
  },
  tab: {
    flex: 1,
    padding: '15px',
    border: 'none',
    background: 'none',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500',
    color: '#666',
    borderBottom: '3px solid transparent',
    transition: 'all 0.2s',
  },
  tabActive: {
    color: '#667eea',
    borderBottomColor: '#667eea',
    background: 'white',
  },
  tabContent: {
    flex: 1,
    overflowY: 'auto',
    padding: '30px',
  },
  infoGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
    gap: '20px',
    marginBottom: '30px',
  },
  infoCard: {
    padding: '20px',
    background: '#f9f9f9',
    borderRadius: '8px',
    border: '1px solid #e0e0e0',
  },
  infoLabel: {
    fontSize: '12px',
    color: '#666',
    marginBottom: '8px',
    textTransform: 'uppercase',
    fontWeight: '600',
  },
  infoValue: {
    fontSize: '16px',
    color: '#333',
    fontWeight: '500',
  },
  actions: {
    display: 'flex',
    gap: '15px',
    marginBottom: '30px',
  },
  actionBtn: {
    padding: '12px 24px',
    borderRadius: '6px',
    border: 'none',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
    textDecoration: 'none',
    display: 'inline-block',
    background: '#667eea',
    color: 'white',
    transition: 'transform 0.2s',
  },
  actionBtnWarning: {
    background: '#ff9800',
  },
  actionBtnDanger: {
    background: '#f44336',
  },
  section: {
    marginTop: '30px',
  },
  sectionTitle: {
    marginBottom: '20px',
    fontSize: '18px',
    fontWeight: '600',
  },
  envVars: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
  },
  envVar: {
    display: 'flex',
    alignItems: 'center',
    gap: '15px',
    padding: '12px',
    background: '#f5f5f5',
    borderRadius: '6px',
  },
  envKey: {
    fontFamily: 'monospace',
    fontWeight: '600',
    color: '#667eea',
    minWidth: '150px',
  },
  envValue: {
    fontFamily: 'monospace',
    color: '#333',
  },
  repoInfo: {
    padding: '20px',
    background: '#f9f9f9',
    borderRadius: '8px',
    lineHeight: '2',
  },
  logsHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '20px',
  },
  refreshBtn: {
    padding: '8px 16px',
    background: '#667eea',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '14px',
  },
  logs: {
    background: '#1e1e1e',
    color: '#d4d4d4',
    padding: '20px',
    borderRadius: '8px',
    fontSize: '13px',
    fontFamily: 'monospace',
    overflowX: 'auto',
    whiteSpace: 'pre-wrap',
    maxHeight: '500px',
    overflowY: 'auto',
  },
  settings: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  settingRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '20px',
    background: '#f9f9f9',
    borderRadius: '8px',
  },
  settingLabel: {
    fontSize: '16px',
    fontWeight: '600',
    marginBottom: '5px',
  },
  settingDesc: {
    fontSize: '14px',
    color: '#666',
  },
  settingValue: {
    fontSize: '14px',
    fontWeight: '500',
  },
};

export default DeploymentDetails;