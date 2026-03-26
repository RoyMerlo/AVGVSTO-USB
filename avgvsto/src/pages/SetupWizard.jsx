import React, { useState } from 'react';
import { Button } from '../components/Button';
import { Input } from '../components/Input';

export function SetupWizard({ onComplete }) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState({
    businessName: '',
    password: '',
    confirmPassword: '',
  });

  const handleNext = () => {
    if (step === 1 && formData.businessName.trim() === '') return;
    if (step === 2 && (formData.password.length < 8 || formData.password !== formData.confirmPassword)) return;
    setStep(step + 1);
  };

  const handleFinish = async () => {
    // In a real app we would call the Tauri backend here:
    // await invoke('hash_password', { password: formData.password });
    onComplete(formData);
  };

  return (
    <div style={{ maxWidth: '400px', width: '100%', textAlign: 'left' }}>
      <div style={{ marginBottom: '2rem' }}>
        <h2 style={{ fontSize: '1.5rem', marginBottom: '0.5rem', color: 'var(--primary-color)' }}>
          STEP 0{step} // {step === 1 ? 'IDENTIFICATION' : step === 2 ? 'MASTER KEY' : 'HARDWARE BINDING'}
        </h2>
        <div style={{ height: '2px', background: 'var(--border-dark)', width: '100%' }}>
          <div style={{ height: '100%', background: 'var(--primary-color)', width: `${(step / 3) * 100}%`, transition: 'width 0.3s' }} />
        </div>
      </div>

      {step === 1 && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
            Initialize the AVGVSTO offline vault for your organization. Data sovereignty begins here.
          </p>
          <Input 
            label="BUSINESS / ORGANIZATION NAME" 
            value={formData.businessName} 
            onChange={(e) => setFormData({ ...formData, businessName: e.target.value })}
            placeholder="e.g. Acme Corp Legal"
          />
          <Button onClick={handleNext} disabled={!formData.businessName.trim()} className="w-full" style={{ width: '100%' }}>
            PROCEED
          </Button>
        </div>
      )}

      {step === 2 && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
            Establish the master administrative password. This is hashed via Argon2 and cannot be recovered if lost.
          </p>
          <Input 
            label="MASTER PASSWORD" 
            type="password"
            value={formData.password} 
            onChange={(e) => setFormData({ ...formData, password: e.target.value })}
          />
          <Input 
            label="CONFIRM MASTER PASSWORD" 
            type="password"
            value={formData.confirmPassword} 
            onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
          />
          <div style={{ display: 'flex', gap: '1rem' }}>
            <Button onClick={() => setStep(1)} variant="secondary" style={{ flex: 1 }}>BACK</Button>
            <Button 
              onClick={handleNext} 
              disabled={formData.password.length < 8 || formData.password !== formData.confirmPassword} 
              style={{ flex: 1 }}
            >
              SECURE KEY
            </Button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div>
          <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
            AVGVSTO requires a physical USB drive to be registered as the hardware key. Insert a secure USB drive now.
          </p>
          <div style={{ padding: '1.5rem', border: '1px dashed var(--border-dark)', borderRadius: '4px', textAlign: 'center', marginBottom: '2rem' }}>
            <p style={{ color: 'var(--primary-color)', fontFamily: 'monospace' }}>SCANNING FOR HARDWARE_ID...</p>
          </div>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <Button onClick={() => setStep(2)} variant="secondary" style={{ flex: 1 }}>BACK</Button>
            <Button onClick={handleFinish} style={{ flex: 1 }}>INITIALIZE VAULT</Button>
          </div>
        </div>
      )}
    </div>
  );
}
