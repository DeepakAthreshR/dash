import { useState } from 'react';

function RollbackManager({ deploymentId, versions, onRollback }) {
  const [loading, setLoading] = useState(false);
  const [selectedVersion, setSelectedVersion] = useState(null);

  const handleRollback = async (version) => {
    if (!confirm(`⚠️ Rollback to Version ${version}?\n\nThis will stop the current deployment and start the previous version.`)) {
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`/api/deployments/${deploymentId}/rollback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ version })
      });

      const data = await response.json();

      if (response.ok) {
        alert(`✅ ${data.message}`);
        if (onRollback) onRollback();
      } else {
        alert(`❌ Rollback failed: ${data.error}`);
      }
    } catch (error) {
      alert(`❌ Rollback failed: ${error.message}`);
    } finally {
      setLoading(false);
    }
  };

  if (!versions || versions.length === 0) {
    return (
      <div style={styles.container}>
        <h2 style={styles.title}>⏮️ Version History</h2>
        <div style={styles.empty}>
          <div style={styles.emptyIcon}>📦</div>
          <div style={styles.emptyText}>No previous versions available</div>
          <div style={styles.emptyHint}>
            Deploy a new version to see version history here
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>⏮️ Version History</h2>
      
      <div style={styles.info}>
        <strong>💡 About Rollback:</strong> You can rollback to any previous version. 
        The platform keeps the last 10 deployment versions for quick recovery.
      </div>

      <div style={styles.versionsList}>
        {versions.map((version) => (
          <div 
            key={version.version} 
            style={{
              ...styles.versionCard,
              ...(selectedVersion === version.version ? styles.versionCardSelected : {})
            }}
            onClick={() => setSelectedVersion(version.version)}
          >
            <div style={styles.versionHeader}>
              <div style={styles.versionBadge}>
                Version {version.version}
              </div>
              <div style={styles.versionStatus}>
                {version.status === 'previous' ? '📦 Previous' : '✅ Current'}
              </div>
            </div>

            <div style={styles.versionInfo}>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Container ID:</span>
                <code style={styles.infoValue}>
                  {/* ✅ FIX: Check if containerId exists before substring */}
                  {version.containerId ? version.containerId.substring(0, 12) : 'Pending...'}
                </code>
              </div>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Deployed:</span>
                <span style={styles.infoValue}>
                  {new Date(version.timestamp).toLocaleString()}
                </span>
              </div>
              <div style={styles.infoRow}>
                <span style={styles.infoLabel}>Config:</span>
                <span style={styles.infoValue}>
                  {Object.keys(version.config || {}).length} settings
                </span>
              </div>
            </div>

            <button
              onClick={(e) => {
                e.stopPropagation();
                handleRollback(version.version);
              }}
              disabled={loading || !version.containerId} // Disable if no container
              style={{
                ...styles.rollbackBtn,
                ...(loading || !version.containerId ? styles.rollbackBtnDisabled : {})
              }}
            >
              {loading ? '⏳ Rolling back...' : `⏮️ Rollback to v${version.version}`}
            </button>
          </div>
        ))}
      </div>

      <div style={styles.warning}>
        <strong>⚠️ Important:</strong>
        <ul style={styles.warningList}>
          <li>Rollback will stop the current deployment</li>
          <li>The previous container will be restarted</li>
          <li>Environment variables from that version will be restored</li>
          <li>This action can be undone by rolling back again</li>
        </ul>
      </div>
    </div>
  );
}

const styles = {
  container: {
    padding: '20px',
  },
  title: {
    marginBottom: '20px',
    fontSize: '24px',
  },
  info: {
    padding: '15px',
    background: '#e3f2fd',
    border: '1px solid #2196f3',
    borderRadius: '8px',
    marginBottom: '20px',
    fontSize: '14px',
    color: '#1565c0',
  },
  empty: {
    textAlign: 'center',
    padding: '60px 20px',
    color: '#999',
  },
  emptyIcon: {
    fontSize: '64px',
    marginBottom: '20px',
  },
  emptyText: {
    fontSize: '18px',
    fontWeight: '600',
    marginBottom: '10px',
    color: '#666',
  },
  emptyHint: {
    fontSize: '14px',
    color: '#999',
  },
  versionsList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '15px',
  },
  versionCard: {
    padding: '20px',
    border: '2px solid #e0e0e0',
    borderRadius: '8px',
    cursor: 'pointer',
    transition: 'all 0.2s',
    background: 'white',
  },
  versionCardSelected: {
    borderColor: '#667eea',
    boxShadow: '0 4px 8px rgba(102, 126, 234, 0.2)',
  },
  versionHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '15px',
  },
  versionBadge: {
    padding: '6px 12px',
    background: '#667eea',
    color: 'white',
    borderRadius: '4px',
    fontSize: '14px',
    fontWeight: '600',
  },
  versionStatus: {
    fontSize: '14px',
    color: '#666',
  },
  versionInfo: {
    display: 'flex',
    flexDirection: 'column',
    gap: '10px',
    marginBottom: '15px',
    padding: '15px',
    background: '#f9f9f9',
    borderRadius: '6px',
  },
  infoRow: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    fontSize: '14px',
  },
  infoLabel: {
    fontWeight: '600',
    color: '#555',
  },
  infoValue: {
    color: '#333',
    fontFamily: 'monospace',
  },
  rollbackBtn: {
    width: '100%',
    padding: '12px',
    background: '#ff9800',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '14px',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'background 0.2s',
  },
  rollbackBtnDisabled: {
    background: '#ccc',
    cursor: 'not-allowed',
  },
  warning: {
    marginTop: '30px',
    padding: '20px',
    background: '#fff3cd',
    border: '1px solid #ffc107',
    borderRadius: '8px',
    fontSize: '14px',
    color: '#856404',
  },
  warningList: {
    margin: '10px 0 0 0',
    paddingLeft: '20px',
    lineHeight: '1.8',
  },
};

export default RollbackManager;