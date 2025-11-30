import { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

function MetricsDashboard({ deploymentId }) {
  const [metrics, setMetrics] = useState([]);
  const [currentStats, setCurrentStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchMetrics();
    fetchCurrentStats();
    
    const interval = setInterval(() => {
      fetchCurrentStats();
    }, 5000); // Update every 5 seconds
    
    return () => clearInterval(interval);
  }, [deploymentId]);

  const fetchMetrics = async () => {
    try {
      const response = await fetch(`/api/deployments/${deploymentId}/metrics?hours=24`);
      const data = await response.json();
      setMetrics(data.metrics || []);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch metrics:', error);
      setLoading(false);
    }
  };

  const fetchCurrentStats = async () => {
    try {
      const response = await fetch(`/api/deployments/${deploymentId}/stats`);
      const data = await response.json();
      
      const stats = {
        cpu: ((data.cpu_stats?.cpu_usage?.total_usage || 0) / 1000000).toFixed(2),
        memory: ((data.memory_stats?.usage || 0) / 1024 / 1024).toFixed(2),
        networkRx: ((data.networks?.eth0?.rx_bytes || 0) / 1024 / 1024).toFixed(2),
        networkTx: ((data.networks?.eth0?.tx_bytes || 0) / 1024 / 1024).toFixed(2),
      };
      
      setCurrentStats(stats);
    } catch (error) {
      console.error('Failed to fetch stats:', error);
    }
  };

  if (loading) {
    return <div style={styles.loading}>Loading metrics...</div>;
  }

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>📊 Performance Metrics</h2>

      {/* Current Stats Cards */}
      <div style={styles.statsGrid}>
        <div style={styles.statCard}>
          <div style={styles.statIcon}>⚙️</div>
          <div style={styles.statLabel}>CPU Usage</div>
          <div style={styles.statValue}>{currentStats?.cpu || '0'}%</div>
        </div>
        
        <div style={styles.statCard}>
          <div style={styles.statIcon}>💾</div>
          <div style={styles.statLabel}>Memory</div>
          <div style={styles.statValue}>{currentStats?.memory || '0'} MB</div>
        </div>
        
        <div style={styles.statCard}>
          <div style={styles.statIcon}>⬇️</div>
          <div style={styles.statLabel}>Network RX</div>
          <div style={styles.statValue}>{currentStats?.networkRx || '0'} MB</div>
        </div>
        
        <div style={styles.statCard}>
          <div style={styles.statIcon}>⬆️</div>
          <div style={styles.statLabel}>Network TX</div>
          <div style={styles.statValue}>{currentStats?.networkTx || '0'} MB</div>
        </div>
      </div>

      {/* Historical Charts */}
      {metrics.length > 0 && (
        <div style={styles.chartsContainer}>
          <div style={styles.chartBox}>
            <h3 style={styles.chartTitle}>CPU Usage Over Time</h3>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={metrics.reverse()}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="timestamp" 
                  tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="cpu" stroke="#8884d8" name="CPU %" />
              </LineChart>
            </ResponsiveContainer>
          </div>

          <div style={styles.chartBox}>
            <h3 style={styles.chartTitle}>Memory Usage Over Time</h3>
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={metrics}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="timestamp" 
                  tickFormatter={(time) => new Date(time).toLocaleTimeString()}
                />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="memory" stroke="#82ca9d" name="Memory (MB)" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
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
    padding: '40px',
    fontSize: '16px',
    color: '#666',
  },
  title: {
    marginBottom: '20px',
    fontSize: '24px',
  },
  statsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: '20px',
    marginBottom: '30px',
  },
  statCard: {
    padding: '20px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    borderRadius: '12px',
    color: 'white',
    boxShadow: '0 4px 6px rgba(0,0,0,0.1)',
  },
  statIcon: {
    fontSize: '32px',
    marginBottom: '10px',
  },
  statLabel: {
    fontSize: '14px',
    opacity: 0.9,
    marginBottom: '5px',
  },
  statValue: {
    fontSize: '28px',
    fontWeight: 'bold',
  },
  chartsContainer: {
    display: 'flex',
    flexDirection: 'column',
    gap: '30px',
  },
  chartBox: {
    padding: '20px',
    background: 'white',
    borderRadius: '8px',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
  },
  chartTitle: {
    marginBottom: '15px',
    fontSize: '18px',
  },
};

export default MetricsDashboard;
