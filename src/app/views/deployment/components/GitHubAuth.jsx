import React, { useState, useEffect } from 'react';
import axios from 'axios';

// Use relative path - nginx-lb will route /api to backends
const API_BASE = import.meta?.env?.VITE_API_URL || '';

export default function GitHubAuth({ onLogin, onLogout, user, loggedIn }) {
  const [token, setToken] = useState('');
  const [error, setError] = useState('');

  // Check for existing session on component mount
  useEffect(() => {
    const checkSession = async () => {
      try {
        const res = await axios.get(`${API_BASE}/api/check-github-session`, { withCredentials: true });
        if (res.data.authenticated && res.data.username) {
          onLogin(res.data.username);
        }
      } catch (err) {
        // Session check failed, user not logged in
        console.log('No active GitHub session');
      }
    };
    checkSession();
  }, [onLogin]);

  const handleLogin = async () => {
    setError('');
    try {
      const res = await axios.post(`${API_BASE}/api/login/github`, { token }, { withCredentials: true });
      onLogin(res.data.username);
      setToken('');
    } catch (err) {
      setError('Invalid token');
    }
  };

  const handleLogout = async () => {
    await axios.post(`${API_BASE}/api/logout/github`, {}, { withCredentials: true });
    onLogout();
  };

  if (loggedIn) {
    return (
      <div>
        <span>Logged in as <b>{user}</b></span>
        <button onClick={handleLogout}>Logout</button>
      </div>
    );
  }

  return (
    <div>
      <input
        type="password"
        placeholder="GitHub Personal Access Token"
        value={token}
        onChange={e => setToken(e.target.value)}
      />
      <button onClick={handleLogin}>Login with GitHub</button>
      {error && <span style={{ color: 'red' }}>{error}</span>}
      <div>
        <small>
          <a href="https://github.com/settings/tokens" target="_blank" rel="noopener noreferrer">
            Get a GitHub token
          </a>
        </small>
      </div>
    </div>
  );
}
