import { useState } from 'react';
// Correct relative imports assuming components are in ./components/ relative to this file
import GitHubAuth from './components/GitHubAuth';
import DeploymentForm from './components/DeploymentForm';
import DeploymentsList from './components/DeploymentsList';
import './DeploymentApp.css'; 

export default function DeploymentApp() {
  const [activeTab, setActiveTab] = useState('new');
  const [refreshKey, setRefreshKey] = useState(0);
  const [githubLoggedIn, setGithubLoggedIn] = useState(false);
  const [githubUser, setGithubUser] = useState('');

  const handleDeploymentSuccess = (result) => {
    console.log('Deployment successful:', result);
    setActiveTab('list');
    setRefreshKey(prev => prev + 1);
  };

  const handleLogin = (username) => {
    setGithubLoggedIn(true);
    setGithubUser(username);
  };

  const handleLogout = () => {
    setGithubLoggedIn(false);
    setGithubUser('');
  };

  return (
    <div className="deployment-app-container">
      <header className="app-header">
        <h1>Deployment Platform</h1>
        <p className="subtitle">Deploy with Environment Variables, Rollback, Metrics & Custom Domains</p>
        <GitHubAuth 
          onLogin={handleLogin} 
          onLogout={handleLogout} 
          user={githubUser} 
          loggedIn={githubLoggedIn} 
        />
      </header>

      <nav className="app-nav">
        <button 
          className={activeTab === 'new' ? 'active' : ''}
          onClick={() => setActiveTab('new')}
        >
          ➕ New Deployment
        </button>
        <button 
          className={activeTab === 'list' ? 'active' : ''}
          onClick={() => setActiveTab('list')}
        >
          📦 My Deployments
        </button>
      </nav>

      <main className="app-main">
        {activeTab === 'new' ? (
          <DeploymentForm 
            onDeploy={handleDeploymentSuccess} 
            githubLoggedIn={githubLoggedIn} 
            githubUser={githubUser} 
          />
        ) : (
          <DeploymentsList refreshKey={refreshKey} />
        )}
      </main>

      <footer className="app-footer">
        <p>✨ Features: Env Variables | Rollback | Metrics | Persistent Volumes | Custom Domains</p>
      </footer>
    </div>
  );
}