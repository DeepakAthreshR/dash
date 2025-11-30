import { useState } from 'react';

function EnvVariablesManager({ variables, onChange }) {
  const [envVars, setEnvVars] = useState(variables || []);

  const addVariable = () => {
    const newVars = [...envVars, { key: '', value: '', isSecret: false }];
    setEnvVars(newVars);
    onChange(newVars);
  };

  const removeVariable = (index) => {
    const newVars = envVars.filter((_, i) => i !== index);
    setEnvVars(newVars);
    onChange(newVars);
  };

  const updateVariable = (index, field, value) => {
    const newVars = [...envVars];
    newVars[index][field] = value;
    setEnvVars(newVars);
    onChange(newVars);
  };

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <h3 style={styles.title}>🔐 Environment Variables</h3>
        <button type="button" onClick={addVariable} style={styles.addButton}>
          + Add Variable
        </button>
      </div>

      {envVars.length === 0 && (
        <p style={styles.emptyMessage}>No environment variables defined</p>
      )}

      {envVars.map((envVar, index) => (
        <div key={index} style={styles.varRow}>
          <input
            type="text"
            placeholder="KEY"
            value={envVar.key}
            onChange={(e) => updateVariable(index, 'key', e.target.value.toUpperCase())}
            style={styles.keyInput}
          />
          <input
            type={envVar.isSecret ? 'password' : 'text'}
            placeholder="value"
            value={envVar.value}
            onChange={(e) => updateVariable(index, 'value', e.target.value)}
            style={styles.valueInput}
          />
          <label style={styles.secretLabel}>
            <input
              type="checkbox"
              checked={envVar.isSecret}
              onChange={(e) => updateVariable(index, 'isSecret', e.target.checked)}
            />
            <span style={styles.secretText}>Secret</span>
          </label>
          <button
            type="button"
            onClick={() => removeVariable(index)}
            style={styles.removeButton}
          >
            ×
          </button>
        </div>
      ))}
    </div>
  );
}

const styles = {
  container: {
    margin: '20px 0',
    padding: '20px',
    border: '1px solid #e0e0e0',
    borderRadius: '8px',
    background: '#f9f9f9',
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: '15px',
  },
  title: {
    margin: 0,
    fontSize: '16px',
    fontWeight: '600',
  },
  addButton: {
    padding: '8px 16px',
    background: '#0066ff',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: '500',
  },
  emptyMessage: {
    textAlign: 'center',
    color: '#666',
    padding: '20px',
    fontStyle: 'italic',
  },
  varRow: {
    display: 'flex',
    gap: '10px',
    marginBottom: '10px',
    alignItems: 'center',
  },
  keyInput: {
    flex: '0 0 200px',
    padding: '10px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontFamily: 'monospace',
    fontSize: '14px',
    textTransform: 'uppercase',
  },
  valueInput: {
    flex: 1,
    padding: '10px',
    border: '1px solid #ddd',
    borderRadius: '4px',
    fontFamily: 'monospace',
    fontSize: '14px',
  },
  secretLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '5px',
    whiteSpace: 'nowrap',
    cursor: 'pointer',
  },
  secretText: {
    fontSize: '14px',
    color: '#666',
  },
  removeButton: {
    padding: '8px 12px',
    background: '#ff4444',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '18px',
    lineHeight: '1',
  },
};

export default EnvVariablesManager;
