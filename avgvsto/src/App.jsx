import React, { useState } from 'react';
import { SetupWizard } from './pages/SetupWizard';

function App() {
  const [isSetupComplete, setIsSetupComplete] = useState(false);

  const handleSetupComplete = (data) => {
    console.log("Vault Initialized for:", data.businessName);
    setIsSetupComplete(true);
  };

  return (
    <div className="layout">
      <main className="main-content">
        <h1 className="title">AVGVSTO 4.0</h1>
        <p className="subtitle">100% Offline, Hardware-Bound Encryption</p>
        
        {!isSetupComplete ? (
          <SetupWizard onComplete={handleSetupComplete} />
        ) : (
          <div className="status-box">
            <p>Vault Access Granted.</p>
            <p style={{ color: 'var(--text-secondary)', marginTop: '1rem', fontSize: '0.9rem' }}>
              System is operating strictly offline.
            </p>
          </div>
        )}
      </main>
    </div>
  );
}

export default App;
