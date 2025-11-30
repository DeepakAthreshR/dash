import { useState } from 'react';

function CustomDomainManager({ deploymentId, currentDomain, onUpdate }) {
  const [domain, setDomain] = useState('');
  const [cloudflareApiKey, setCloudflareApiKey] = useState('');
  const [cloudflareZoneId, setCloudflareZoneId] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleAddDomain = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const response = await fetch(`/api/deployments/${deploymentId}/domain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          domain,
          cloudflareApiKey,
          cloudflareZoneId
        })
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess(`✅ Custom domain ${domain} added successfully!`);
        setDomain('');
        setCloudflareApiKey('');
        setCloudflareZoneId('');
        if (onUpdate) onUpdate();
      } else {
        setError(data.error || 'Failed to add custom domain');
      }
    } catch (err) {
      setError(`Error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>🌐 Custom Domain</h2>
      
      {currentDomain && (
        <div style={styles.currentDomain}>
          <div style={styles.currentLabel}>Current Domain:</div>
          <div style={styles.domainValue}>
            <a 
              href={`https://${currentDomain.domain}`} 
              target="_blank" 
              rel="noopener noreferrer"
              style={styles.link}
            >
              {currentDomain.domain}
            </a>
            <span style={{...styles.badge, ...styles[`badge_${currentDomain.status}`]}}>
              {currentDomain.status}
            </span>
          </div>
        </div>
      )}

      <div style={styles.info}>
        <h3 style={styles.infoTitle}>📋 How to Set Up Custom Domain</h3>
        <ol style={styles.steps}>
          <li>Get your Cloudflare API Token from your Cloudflare dashboard</li>
          <li>Find your Zone ID in Cloudflare (Overview → Zone ID)</li>
          <li>Enter your custom domain below</li>
          <li>Click "Add Domain" to create DNS records automatically</li>
        </ol>
      </div>

      <form onSubmit={handleAddDomain} style={styles.form}>
        <div style={styles.formGroup}>
          <label style={styles.label}>Domain Name</label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com or app.example.com"
            required
            style={styles.input}
          />
        </div>

        <div style={styles.formGroup}>
          <label style={styles.label}>Cloudflare API Token</label>
          <input
            type="password"
            value={cloudflareApiKey}
            onChange={(e) => setCloudflareApiKey(e.target.value)}
            placeholder="Your Cloudflare API Token"
            required
            style={styles.input}
          />
          <small style={styles.hint}>
            Get from: Cloudflare Dashboard → My Profile → API Tokens
          </small>
        </div>

        <div style={styles.formGroup}>
          <label style={styles.label}>Cloudflare Zone ID</label>
          <input
            type="text"
            value={cloudflareZoneId}
            onChange={(e) => setCloudflareZoneId(e.target.value)}
            placeholder="Your Cloudflare Zone ID"
            required
            style={styles.input}
          />
          <small style={styles.hint}>
            Get from: Cloudflare Dashboard → Select Domain → Overview → Zone ID
          </small>
        </div>

        {error && <div style={styles.error}>{error}</div>}
        {success && <div style={styles.success}>{success}</div>}

        <button 
          type="submit" 
          disabled={loading}
          style={{...styles.button, ...(loading ? styles.buttonDisabled : {})}}
        >
          {loading ? '⏳ Adding Domain...' : '➕ Add Custom Domain'}
        </button>
      </form>

      <div style={styles.warning}>
        <strong>⚠️ Note:</strong> Make sure your server's IP address is correct in the DNS configuration. 
        The default is set to 127.0.0.1 (localhost). Update it to your actual server IP.
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
  currentDomain: {
    padding: '20px',
    background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    borderRadius: '8px',
    color: 'white',
    marginBottom: '30px',
  },
  currentLabel: {
    fontSize: '14px',
    opacity: 0.9,
    marginBottom: '8px',
  },
  domainValue: {
    display: 'flex',
    alignItems: 'center',
    gap: '15px',
    fontSize: '20px',
    fontWeight: '600',
  },
  link: {
    color: 'white',
    textDecoration: 'none',
    borderBottom: '2px solid rgba(255,255,255,0.5)',
  },
  badge: {
    padding: '4px 12px',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: '600',
    textTransform: 'uppercase',
    background: 'rgba(255,255,255,0.2)',
  },
  badge_active: {
    background: '#4caf50',
  },
  info: {
    padding: '20px',
    background: '#f0f4ff',
    borderRadius: '8px',
    marginBottom: '30px',
    border: '1px solid #d0deff',
  },
  infoTitle: {
    margin: '0 0 15px 0',
    fontSize: '16px',
    color: '#667eea',
  },
  steps: {
    margin: 0,
    paddingLeft: '20px',
    lineHeight: '1.8',
    color: '#555',
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '20px',
  },
  formGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
  },
  label: {
    fontSize: '14px',
    fontWeight: '600',
    color: '#333',
  },
  input: {
    padding: '12px',
    border: '1px solid #ddd',
    borderRadius: '6px',
    fontSize: '14px',
    fontFamily: 'inherit',
  },
  hint: {
    fontSize: '12px',
    color: '#666',
    fontStyle: 'italic',
  },
  button: {
    padding: '14px 28px',
    background: '#667eea',
    color: 'white',
    border: 'none',
    borderRadius: '6px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    transition: 'transform 0.2s',
  },
  buttonDisabled: {
    background: '#ccc',
    cursor: 'not-allowed',
  },
  error: {
    padding: '12px',
    background: '#ffebee',
    border: '1px solid #f44336',
    borderRadius: '6px',
    color: '#c62828',
    fontSize: '14px',
  },
  success: {
    padding: '12px',
    background: '#e8f5e9',
    border: '1px solid #4caf50',
    borderRadius: '6px',
    color: '#2e7d32',
    fontSize: '14px',
  },
  warning: {
    marginTop: '20px',
    padding: '15px',
    background: '#fff3cd',
    border: '1px solid #ffc107',
    borderRadius: '6px',
    fontSize: '14px',
    color: '#856404',
  },
};

export default CustomDomainManager;
