import { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import { 
  Box, 
  Button, 
  Card, 
  Grid, 
  TextField, 
  Radio, 
  RadioGroup, 
  FormControlLabel, 
  FormControl, 
  FormLabel, 
  Typography,
  Alert,
  CircularProgress,
  Divider,
  MenuItem,
  LinearProgress
} from "@mui/material";
import { styled } from "@mui/material/styles";
import { CloudUpload } from "@mui/icons-material";

// Sub-components
import StaticSiteConfig from './StaticSiteConfig';
import WebServiceConfig from './WebServiceConfig';
import EnvVariablesManager from './EnvVariablesManager';
import AutoDetectBanner from './AutoDetectBanner';

// Custom Styled Components
const FormSection = styled(Box)(({ theme }) => ({
  marginBottom: "2rem",
}));

const LogContainer = styled(Box)(({ theme }) => ({
  backgroundColor: "#1e1e1e",
  color: "#d4d4d4",
  padding: "1rem",
  borderRadius: "8px",
  fontFamily: "monospace",
  fontSize: "0.85rem",
  maxHeight: "400px",
  overflowY: "auto",
  marginTop: "1rem",
  border: "1px solid #333"
}));

function DeploymentForm({ onDeploy, githubLoggedIn, githubUser }) {
  const API_BASE = import.meta?.env?.VITE_API_URL || '';
  const [deploymentSource, setDeploymentSource] = useState('github');
  const [githubRepos, setGithubRepos] = useState([]);
  const [deploymentType, setDeploymentType] = useState('static');
  const [projectName, setProjectName] = useState('');
  const [githubRepo, setGithubRepo] = useState('');
  const [branch, setBranch] = useState('main');
  const [uploadedFile, setUploadedFile] = useState(null);
  
  // Detection State
  const [isDetecting, setIsDetecting] = useState(false);
  const [detectionResult, setDetectionResult] = useState(null);

  // Config State
  const [environmentVariables, setEnvironmentVariables] = useState([]);
  const [persistentStorage, setPersistentStorage] = useState(false);
  const [healthCheckPath, setHealthCheckPath] = useState('/');
  const [autoRestart, setAutoRestart] = useState(true);
  
  const [staticConfig, setStaticConfig] = useState({
    buildCommand: 'npm install && npm run build',
    publishDir: 'dist',
    entryFile: 'index.html'
  });
  
  const [webServiceConfig, setWebServiceConfig] = useState({
    runtime: 'python',
    entryFile: 'app.py',
    buildCommand: '',
    startCommand: '',
    port: '5000',
    javaType: 'jar',
    useDevMode: false
  });
  
  const [status, setStatus] = useState({ type: '', message: '' });
  const [isDeploying, setIsDeploying] = useState(false);
  const [buildLogs, setBuildLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);
  const logsEndRef = useRef(null);

  useEffect(() => {
    if (githubLoggedIn) {
      axios.get(`${API_BASE}/api/user/repos`, { withCredentials: true })
        .then(res => setGithubRepos(res.data.repositories))
        .catch(() => setGithubRepos([]));
    }
  }, [githubLoggedIn]);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [buildLogs]);

  const addLog = (type, message) => {
    const timestamp = new Date().toLocaleTimeString();
    setBuildLogs(prev => [...prev, { type, message, timestamp }]);
  };

  // --- Reusable Stream Processor ---
  const processStreamResponse = async (response) => {
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      for (const line of lines) {
        if (line.startsWith('data: ')) {
          try {
            const data = JSON.parse(line.slice(6));
            if (data.type === 'log' || data.type === 'info') addLog('info', data.message);
            else if (data.type === 'success') addLog('success', data.message);
            else if (data.type === 'error') addLog('error', data.message);
            else if (data.type === 'done') {
              if (data.success) {
                setStatus({ type: 'success', message: '✅ Deployment successful!' });
                onDeploy(data.deployment);
              } else {
                setStatus({ type: 'error', message: `❌ Deployment failed: ${data.error}` });
              }
            }
          } catch (e) { console.error('Parse error:', e); }
        }
      }
    }
  };

  const runDetection = async (sourceType, payload) => {
    setIsDetecting(true);
    setDetectionResult(null);

    try {
      let response;
      if (sourceType === 'local') {
        const formData = new FormData();
        formData.append('file', payload);
        response = await axios.post(`${API_BASE}/api/detect-project`, formData, { withCredentials: true });
      } else {
        response = await axios.post(`${API_BASE}/api/detect-github`, {
          githubRepo: payload,
          branch
        }, { withCredentials: true });
      }

      if (response.data && response.data.success) {
        const { detection, suggestions } = response.data;
        setDeploymentType(detection.type);
        
        if (detection.type === 'static') {
          setStaticConfig(prev => ({
            ...prev,
            buildCommand: detection.config.buildCommand || prev.buildCommand,
            publishDir: detection.config.publishDir || prev.publishDir
          }));
        } else {
          setWebServiceConfig(prev => ({
            ...prev,
            runtime: detection.runtime,
            entryFile: detection.config.entryFile || prev.entryFile,
            port: detection.config.port || prev.port,
            startCommand: detection.config.startCommand || prev.startCommand,
            buildCommand: detection.config.buildCommand || ''
          }));
        }

        setDetectionResult({ suggestions });
        setStatus({ type: 'success', message: '✅ Configuration auto-filled based on project analysis.' });
      }
    } catch (error) {
      console.error('Detection failed:', error);
    } finally {
      setIsDetecting(false);
    }
  };

  const handleRepoSelect = (e) => {
    const idx = e.target.value;
    if (idx !== '') {
      const selectedRepo = githubRepos[idx];
      setGithubRepo(selectedRepo.clone_url);
      if (selectedRepo.default_branch) setBranch(selectedRepo.default_branch);
      setDeploymentSource('github');
      runDetection('github', selectedRepo.clone_url);
    }
  };

  const handleUrlBlur = () => {
    if (githubRepo && githubRepo.startsWith('http')) {
        runDetection('github', githubRepo);
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (!file.name.endsWith('.zip')) {
        setStatus({ type: 'error', message: '❌ Only .zip files are supported' });
        e.target.value = '';
        return;
      }
      setUploadedFile(file);
      setStatus({ type: 'success', message: `✅ File selected: ${file.name}` });
      runDetection('local', file);
    }
  };

  const handleDeploy = async (e) => {
    e.preventDefault();
    if (!projectName) {
      setStatus({ type: 'error', message: '❌ Please enter a project name' });
      return;
    }

    setIsDeploying(true);
    setBuildLogs([]);
    setShowLogs(true);
    setStatus({ type: 'loading', message: ' Starting deployment...' });

    try {
      if (deploymentSource === 'github' || deploymentSource === 'github-repo') {
        // --- GitHub Deployment ---
        const deploymentData = {
          projectName,
          githubRepo,
          branch,
          deploymentType,
          config: deploymentType === 'static' ? staticConfig : webServiceConfig,
          environmentVariables,
          persistentStorage,
          healthCheckPath,
          autoRestart
        };

        const response = await fetch(`${API_BASE}/api/deploy-stream`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify(deploymentData)
        });

        if (!response.ok) throw new Error('Failed to start deployment');
        await processStreamResponse(response);

      } else {
        // --- Local ZIP Deployment ---
        addLog('info', '📁 Uploading ZIP file...');
        const formData = new FormData();
        formData.append('file', uploadedFile);
        formData.append('projectName', projectName);
        formData.append('deploymentType', deploymentType);
        formData.append('config', JSON.stringify(deploymentType === 'static' ? staticConfig : webServiceConfig));
        formData.append('environmentVariables', JSON.stringify(environmentVariables));
        formData.append('persistentStorage', persistentStorage.toString());
        formData.append('healthCheckPath', healthCheckPath);
        formData.append('autoRestart', autoRestart.toString());

        const response = await axios.post(`${API_BASE}/api/deploy-local`, formData, { withCredentials: true });
        
        if (response.data && response.data.id) {
            addLog('success', '✅ Upload successful! Queuing build...');
            const deploymentId = response.data.id;
            
            // Connect to the stream endpoint for this deployment
            const streamResponse = await fetch(`${API_BASE}/api/deployments/${deploymentId}/stream`, {
              credentials: 'include'
            });
            
            if (!streamResponse.ok) throw new Error('Failed to connect to log stream');
            await processStreamResponse(streamResponse);
        }
      }
    } catch (error) {
      addLog('error', `❌ Error: ${error.message}`);
      setStatus({ type: 'error', message: `❌ Deployment failed: ${error.message}` });
    } finally {
      setIsDeploying(false);
    }
  };

  return (
    <Card sx={{ p: 4, maxWidth: "100%", margin: "0 auto", boxShadow: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ fontWeight: 600, color: 'primary.main', mb: 3 }}>
        New Deployment
      </Typography>

      <form onSubmit={handleDeploy}>
        
        {/* Source Selection */}
        <FormSection>
          <FormControl component="fieldset">
            <FormLabel component="legend" sx={{ mb: 1, fontWeight: 'bold' }}>Deployment Source</FormLabel>
            <RadioGroup 
              row 
              value={deploymentSource} 
              onChange={e => setDeploymentSource(e.target.value)}
            >
              {githubLoggedIn && (
                <FormControlLabel value="github-repo" control={<Radio />} label="My GitHub Repos" />
              )}
              <FormControlLabel value="local" control={<Radio />} label="Local ZIP Upload" />
              <FormControlLabel value="github" control={<Radio />} label="Public GitHub URL" />
            </RadioGroup>
          </FormControl>
        </FormSection>

        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <TextField
              fullWidth
              label="Project Name"
              variant="outlined"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="my-awesome-app"
              required
            />
          </Grid>

          {/* Source Inputs */}
          {deploymentSource === 'github-repo' && githubLoggedIn ? (
            <Grid item xs={12} md={6}>
              <TextField
                select
                fullWidth
                label="Select Repository"
                onChange={handleRepoSelect}
                helperText="Select one of your GitHub repositories"
              >
                <MenuItem value="" disabled>Select a repository</MenuItem>
                {githubRepos.map((repo, idx) => (
                  <MenuItem key={repo.name} value={idx}>
                    {repo.name} {repo.private ? '(Private)' : ''}
                  </MenuItem>
                ))}
              </TextField>
            </Grid>
          ) : deploymentSource === 'github' ? (
            <>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="GitHub Repository URL"
                  value={githubRepo}
                  onChange={(e) => setGithubRepo(e.target.value)}
                  onBlur={handleUrlBlur} // 👈 Triggers Auto-Detect when clicking away
                  required
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  fullWidth
                  label="Branch"
                  value={branch}
                  onChange={(e) => setBranch(e.target.value)}
                  placeholder="main"
                />
              </Grid>
            </>
          ) : (
            <Grid item xs={12} md={6}>
              <Button
                variant="outlined"
                component="label"
                fullWidth
                startIcon={<CloudUpload />}
                sx={{ height: '56px' }}
              >
                {uploadedFile ? uploadedFile.name : "Upload ZIP File"}
                <input type="file" hidden onChange={handleFileChange} accept=".zip" />
              </Button>
            </Grid>
          )}
        </Grid>

        {/* Loading Bar during Detection */}
        {isDetecting && (
          <Box sx={{ width: '100%', mt: 2 }}>
            <Typography variant="caption" sx={{ color: 'text.secondary' }}> Analyzing project structure...</Typography>
            <LinearProgress />
          </Box>
        )}

        {/* Detection Result Banner - Show suggestions */}
        <Box sx={{ mt: 3 }}>
            <AutoDetectBanner detection={{ suggestions: detectionResult?.suggestions }} />
        </Box>

        <Divider sx={{ my: 4 }} />

        {/* Deployment Type */}
        <FormSection>
          <FormLabel component="legend" sx={{ mb: 1, fontWeight: 'bold' }}>Deployment Type</FormLabel>
          <RadioGroup 
            row 
            value={deploymentType} 
            onChange={e => setDeploymentType(e.target.value)}
          >
            <FormControlLabel value="static" control={<Radio />} label="Static Site" />
            <FormControlLabel value="service" control={<Radio />} label="Web Service" />
          </RadioGroup>
        </FormSection>

        {/* Config Components - These will now be auto-filled */}
        <Box sx={{ mb: 4, p: 3, bgcolor: 'background.default', borderRadius: 2 }}>
          {deploymentType === 'static' ? (
            <StaticSiteConfig config={staticConfig} onChange={setStaticConfig} />
          ) : (
            <WebServiceConfig config={webServiceConfig} onChange={setWebServiceConfig} />
          )}
        </Box>

        {/* Env Vars & Advanced Settings */}
        <Box sx={{ mb: 4 }}>
          <EnvVariablesManager variables={environmentVariables} onChange={setEnvironmentVariables} />
        </Box>

        <Box sx={{ mb: 4, p: 3, bgcolor: '#f0f4ff', borderRadius: 2, border: '1px solid #d0deff' }}>
          <Typography variant="h6" gutterBottom sx={{ color: '#667eea', fontSize: '1rem', fontWeight: 600 }}>
            ⚙️ Advanced Settings
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12}>
              <FormControlLabel 
                control={<input type="checkbox" checked={persistentStorage} onChange={e => setPersistentStorage(e.target.checked)} style={{ marginRight: 10 }} />} 
                label={<Typography variant="body2">Enable Persistent Storage</Typography>} 
              />
            </Grid>
            <Grid item xs={12}>
              <FormControlLabel 
                control={<input type="checkbox" checked={autoRestart} onChange={e => setAutoRestart(e.target.checked)} style={{ marginRight: 10 }} />} 
                label={<Typography variant="body2">Auto-Restart on Failure</Typography>} 
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                size="small"
                label="Health Check Path"
                value={healthCheckPath}
                onChange={e => setHealthCheckPath(e.target.value)}
              />
            </Grid>
          </Grid>
        </Box>

        {status.message && <Alert severity={status.type} sx={{ mb: 2 }}>{status.message}</Alert>}

        <Button 
          type="submit" 
          variant="contained" 
          color="primary" 
          size="large"
          fullWidth
          disabled={isDeploying}
          startIcon={isDeploying ? <CircularProgress size={20} color="inherit" /> : null}
          sx={{ py: 1.5, fontSize: '1.1rem' }}
        >
          {isDeploying ? 'Deploying...' : ' Deploy Project'}
        </Button>

        {showLogs && buildLogs.length > 0 && (
          <LogContainer>
            <Typography variant="subtitle2" sx={{ mb: 1, borderBottom: '1px solid #444', pb: 1 }}>
              📋 Build Logs
            </Typography>
            {buildLogs.map((log, index) => (
              <Box key={index} sx={{ display: 'flex', gap: 1, mb: 0.5 }}>
                <span style={{ color: '#888' }}>[{log.timestamp}]</span>
                <span style={{ color: log.type === 'error' ? '#ff6b6b' : log.type === 'success' ? '#69db7c' : '#d4d4d4' }}>{log.message}</span>
              </Box>
            ))}
            <div ref={logsEndRef} />
          </LogContainer>
        )}
      </form>
    </Card>
  );
}

export default DeploymentForm;