function AutoDetectBanner({ detection }) {
  if (!detection || !detection.suggestions) return null;

  return (
    <div className="alert alert-success" style={{ marginBottom: '1.5rem' }}>
      <h4 style={{ marginBottom: '0.5rem', fontWeight: '600' }}>
        🎯 Auto-Detection Results
      </h4>
      <p style={{ marginBottom: '0.5rem' }}>
        <strong>{detection.suggestions.detected}</strong>
      </p>
      <ul style={{ marginLeft: '1.5rem', marginTop: '0.5rem' }}>
        {detection.suggestions.recommendations.map((rec, i) => (
          <li key={i} style={{ marginBottom: '0.25rem' }}>{rec}</li>
        ))}
      </ul>
    </div>
  );
}

export default AutoDetectBanner;
