import React, { useEffect, useState } from 'react';
import axios from 'axios';

// Use relative path - nginx-lb will route /api to backends
const API_BASE = import.meta?.env?.VITE_API_URL || '';

export default function RepoDeploy({ loggedIn }) {
  const [repos, setRepos] = useState([]);
  const [selected, setSelected] = useState(null);
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (loggedIn) {
      axios.get(`${API_BASE}/api/user/repos`, { withCredentials: true })
        .then(res => setRepos(res.data.repositories))
        .catch(() => setRepos([]));
    }
  }, [loggedIn]);

  const handleDeploy = async () => {
    if (!selected) return;
    setLoading(true);
    setStatus('');
    try {
      const res = await axios.post(`${API_BASE}/deploy/repo`, {
        clone_url: selected.clone_url,
        name: selected.name
      }, { withCredentials: true });
      setStatus(res.data.message || 'Deployment started!');
    } catch (err) {
      setStatus('Deployment failed');
    }
    setLoading(false);
  };

  if (!loggedIn) return null;

  return (
    <div>
      <h3>Deploy from Repository</h3>
      <select onChange={e => setSelected(repos[e.target.value])} defaultValue="">
        <option value="" disabled>Select a repository</option>
        {repos.map((repo, idx) => (
          <option key={repo.name} value={idx}>
            {repo.name} {repo.private ? '(Private)' : ''}
          </option>
        ))}
      </select>
      <button onClick={handleDeploy} disabled={!selected || loading}>
        {loading ? 'Deploying...' : 'Deploy'}
      </button>
      {status && <div>{status}</div>}
    </div>
  );
}
