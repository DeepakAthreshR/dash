import { useState, useEffect } from 'react';
import DeploymentDetails from './DeploymentDetails';

function DeploymentsList({ refreshKey }) {
  const [deployments, setDeployments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDeployment, setSelectedDeployment] = useState(null);

  useEffect(() => {
    fetchDeployments();
  }, [refreshKey]);

  const fetchDeployments = async () => {
    try {
      const response = await fetch('/api/deployments');
      const data = await response.json();
      setDeployments(data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch deployments:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return <div style={styles.loading}>Loading deployments...</div>;
  }

  if (deployments.length === 0) {
    return (
      <div style={styles.empty}>
        <div style={styles.emptyIcon}>📦</div>
        <h3>No deployments yet</h3>
        <p>Deploy your first application to get started!</p>
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <div style={styles.grid}>
        {deployments.map((deployment) => (
          <div 
            key={deployment.id} 
            style={styles.card}
            onClick={() => setSelectedDeployment(deployment.id)}
          >
            <div style={styles.cardHeader}>
              <h3 style={styles.cardTitle}>{deployment.projectName}</h3>
              <span style={{...styles.badge, ...styles[`badge_${deployment.status}`]}}>
                {deployment.status}
              </span>
            </div>

            <div style={styles.cardBody}>
              <div style={styles.info}>
                <span style={styles.label}>Type:</span>
                <span style={styles.value}>{deployment.deploymentType}</span>
              </div>
              <div style={styles.info}>
                <span style={styles.label}>Port:</span>
                <span style={styles.value}>{deployment.port}</span>
              </div>
              <div style={styles.info}>
                <span style={styles.label}>Source:</span>
                <span style={styles.value}>{deployment.source}</span>
              </div>
              <div style={styles.info}>
                <span style={styles.label}>Created:</span>
                <span style={styles.value}>
                  {new Date(deployment.timestamp).toLocaleDateString()}
                </span>
              </div>
              
              {/* NEW: Show features */}
              <div style={styles.features}>
                {deployment.volumePath && <span style={styles.feature}>💾 Volume</span>}
                {deployment.environmentVariables?.length > 0 && (
                  <span style={styles.feature}>🔐 {deployment.environmentVariables.length} Env Vars</span>
                )}
                {deployment.customDomain && <span style={styles.feature}>🌐 Domain</span>}
              </div>
            </div>

            <div style={styles.cardFooter}>
              <a 
                href={deployment.directUrl || deployment.url || `http://localhost:${deployment.port}`} 
                target="_blank" 
                rel="noopener noreferrer"
                style={styles.link}
                onClick={(e) => e.stopPropagation()}
              >
                🌐 Visit {deployment.port ? `(Port ${deployment.port})` : ''}
              </a>
              <button 
                style={styles.detailsBtn}
                onClick={(e) => {
                  e.stopPropagation();
                  setSelectedDeployment(deployment.id);
                }}
              >
                📋 Details
              </button>
            </div>
          </div>
        ))}
      </div>

      {selectedDeployment && (
        <DeploymentDetails
          deploymentId={selectedDeployment}
          onClose={() => setSelectedDeployment(null)}
        />
      )}
    </div>
  );
}

const styles = {
  container: {
    padding: '20px',
  },
  loading: {
    textAlign: 'center',
    padding: '60px',
    fontSize: '18px',
    color: '#666',
  },
  empty: {
    textAlign: 'center',
    padding: '80px 20px',
    color: '#999',
  },
  emptyIcon: {
    fontSize: '64px',
    marginBottom: '20px',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
    gap: '20px',
  },
  card: {
    background: 'white',
    border: '1px solid #e0e0e0',
    borderRadius: '12px',
    overflow: 'hidden',
    cursor: 'pointer',
    transition: 'all 0.3s',
    boxShadow: '0 2px 4px rgba(0,0,0,0.05)',
  },
  cardHeader: {
    padding: '20px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    color: 'white',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  cardTitle: {
    margin: 0,
    fontSize: '18px',
    fontWeight: '600',
  },
  badge: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '11px',
    fontWeight: '600',
    textTransform: 'uppercase',
  },
  badge_active: {
    background: '#4caf50',
  },
  badge_stopped: {
    background: '#ff9800',
  },
  badge_failed: {
    background: '#f44336',
  },
  cardBody: {
    padding: '20px',
  },
  info: {
    display: 'flex',
    justifyContent: 'space-between',
    marginBottom: '10px',
    fontSize: '14px',
  },
  label: {
    color: '#666',
    fontWeight: '500',
  },
  value: {
    color: '#333',
    fontFamily: 'monospace',
  },
  features: {
    display: 'flex',
    gap: '8px',
    flexWrap: 'wrap',
    marginTop: '15px',
  },
  feature: {
    padding: '4px 8px',
    background: '#f0f4ff',
    borderRadius: '4px',
    fontSize: '12px',
    color: '#667eea',
    fontWeight: '500',
  },
  cardFooter: {
    padding: '15px 20px',
    background: '#f9f9f9',
    display: 'flex',
    gap: '10px',
    borderTop: '1px solid #e0e0e0',
  },
  link: {
    flex: 1,
    padding: '10px',
    background: '#667eea',
    color: 'white',
    textDecoration: 'none',
    borderRadius: '6px',
    textAlign: 'center',
    fontSize: '14px',
    fontWeight: '500',
  },
  detailsBtn: {
    flex: 1,
    padding: '10px',
    background: 'white',
    border: '1px solid #667eea',
    color: '#667eea',
    borderRadius: '6px',
    fontSize: '14px',
    fontWeight: '500',
    cursor: 'pointer',
  },
};

export default DeploymentsList;
