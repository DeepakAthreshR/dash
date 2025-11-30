import { Grid, TextField, Typography, Box, Alert } from "@mui/material";

function StaticSiteConfig({ config, onChange }) {
  const handleChange = (field, value) => {
    onChange({ ...config, [field]: value });
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom sx={{ color: 'text.primary', fontSize: '1rem', fontWeight: 600, mb: 2 }}>
        ⚙️ Static Site Configuration
      </Typography>
      
      <Grid container spacing={3}>
        {/* Build Command */}
        <Grid item xs={12}>
          <TextField
            fullWidth
            label="🔨 Build Command"
            value={config.buildCommand || ''}
            onChange={(e) => handleChange('buildCommand', e.target.value)}
            placeholder="npm install && npm run build"
            helperText="Command to install dependencies and build your project"
          />
          
          <Box sx={{ mt: 1, p: 1.5, bgcolor: 'action.hover', borderRadius: 1 }}>
            <Typography variant="caption" display="block" sx={{ fontWeight: 600, mb: 0.5 }}>
              💡 Common Examples:
            </Typography>
            <Grid container spacing={1}>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" display="block" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  • React/Vite: npm install && npm run build
                </Typography>
                <Typography variant="caption" display="block" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  • Next.js: npm install && npm run build && npm run export
                </Typography>
              </Grid>
              <Grid item xs={12} sm={6}>
                <Typography variant="caption" display="block" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  • Create React App: npm install && npm run build
                </Typography>
                <Typography variant="caption" display="block" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  • Plain HTML: echo "No build needed"
                </Typography>
              </Grid>
            </Grid>
          </Box>
        </Grid>

        {/* Publish Directory */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="📂 Publish Directory"
            value={config.publishDir || ''}
            onChange={(e) => handleChange('publishDir', e.target.value)}
            placeholder="dist"
            helperText="The folder containing your built assets (e.g., dist, build, out)"
          />
        </Grid>

        {/* Entry File */}
        <Grid item xs={12} md={6}>
          <TextField
            fullWidth
            label="📄 Entry File (Optional)"
            value={config.entryFile || 'index.html'}
            onChange={(e) => handleChange('entryFile', e.target.value)}
            placeholder="index.html"
            helperText="Default file to serve (usually index.html)"
          />
        </Grid>

        {/* Info Alert */}
        <Grid item xs={12}>
          <Alert severity="info" sx={{ '& .MuiAlert-message': { width: '100%' } }}>
            <Typography variant="subtitle2" gutterBottom sx={{ fontSize: '0.875rem' }}>
              ℹ️ Quick Tips
            </Typography>
            <Typography variant="caption" display="block">
              • <strong>Vite/Vue:</strong> use 'dist' directory
            </Typography>
            <Typography variant="caption" display="block">
              • <strong>React (CRA):</strong> use 'build' directory
            </Typography>
            <Typography variant="caption" display="block">
              • <strong>Plain HTML:</strong> use '.' (dot) for root folder
            </Typography>
          </Alert>
        </Grid>
      </Grid>
    </Box>
  );
}

export default StaticSiteConfig;