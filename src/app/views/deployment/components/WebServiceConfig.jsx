import { Grid, TextField, MenuItem, Typography, Box, Alert } from "@mui/material";

function WebServiceConfig({ config, onChange }) {
  const handleChange = (field, value) => {
    const newConfig = { ...config, [field]: value };
    
    // Auto-adjust defaults based on runtime
    if (field === 'runtime') {
      if (value === 'python') {
        newConfig.entryFile = 'app.py';
        newConfig.port = '5000';
        newConfig.useDevMode = false;
      } else if (value === 'nodejs') {
        newConfig.entryFile = 'index.js';
        newConfig.port = '3000';
      }
    }
    
    onChange(newConfig);
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ color: 'text.primary', fontSize: '1rem', fontWeight: 600, mb: 2 }}>
        ⚙️ Web Service Configuration
      </Typography>
      
      <Grid container spacing={3}>
        {/* Runtime Selection */}
        <Grid item xs={12} md={6}>
          <TextField
            select
            fullWidth
            label="Runtime Environment"
            value={config.runtime || 'python'}
            onChange={(e) => handleChange('runtime', e.target.value)}
            variant="outlined"
          >
            <MenuItem value="python">🐍 Python</MenuItem>
            <MenuItem value="nodejs">💚 Node.js</MenuItem>
          </TextField>
        </Grid>

        {/* Port */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="Application Port"
            value={config.port || ''}
            onChange={(e) => handleChange('port', e.target.value)}
            placeholder={config.runtime === 'python' ? '5000' : '3000'}
            helperText="The port your app listens on (e.g., 5000, 3000)"
          />
        </Grid>

        {/* Entry File */}
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="Entry File"
            value={config.entryFile || ''}
            onChange={(e) => handleChange('entryFile', e.target.value)}
            placeholder={config.runtime === 'python' ? 'app.py' : 'index.js'}
            helperText="The main file that starts your application"
          />
        </Grid>

        {/* Build Command */}
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="🔨 Build Command (Optional)"
            value={config.buildCommand || ''}
            onChange={(e) => handleChange('buildCommand', e.target.value)}
            placeholder={config.runtime === 'python' ? 'pip install -r requirements.txt' : 'npm install'}
          />
          
          <Box sx={{ mt: 1, p: 1.5, bgcolor: 'action.hover', borderRadius: 1 }}>
            <Typography variant="caption" display="block" sx={{ fontWeight: 600, mb: 0.5 }}>
              💡 Common Examples:
            </Typography>
            <Grid container spacing={1}>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" display="block" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  • Python: pip install -r requirements.txt
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" display="block" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  • Node.js: npm install && npm run build
                </Typography>
              </Grid>
            </Grid>
          </Box>
        </Grid>

        {/* Start Command */}
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="🚀 Start Command (Optional)"
            value={config.startCommand || ''}
            onChange={(e) => handleChange('startCommand', e.target.value)}
            disabled={config.useDevMode && config.runtime === 'nodejs'}
            placeholder={config.runtime === 'python' ? 'python app.py' : 'npm start'}
          />
          <Box sx={{ mt: 1 }}>
            <Alert severity="info" sx={{ py: 0, '& .MuiAlert-message': { fontSize: '0.75rem' } }}>
              Leave empty to use the default start command for your runtime.
            </Alert>
          </Box>
        </Grid>
      </Grid>
    </Box>
  );
}

export default WebServiceConfig;