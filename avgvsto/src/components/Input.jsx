import React from 'react';

export function Input({ label, type = 'text', value, onChange, placeholder, required = false }) {
  const containerStyle = {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'flex-start',
    width: '100%',
    marginBottom: '1.5rem',
  };

  const labelStyle = {
    marginBottom: '0.5rem',
    color: 'var(--text-secondary)',
    fontSize: '0.9rem',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
  };

  const inputStyle = {
    width: '100%',
    padding: '0.75rem 1rem',
    backgroundColor: 'rgba(0,0,0,0.5)',
    border: '1px solid var(--border-dark)',
    borderRadius: '4px',
    color: 'var(--text-primary)',
    fontSize: '1rem',
    outline: 'none',
    boxSizing: 'border-box',
    transition: 'border-color 0.2s',
  };

  return (
    <div style={containerStyle}>
      {label && <label style={labelStyle}>{label}</label>}
      <input
        type={type}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        required={required}
        style={inputStyle}
        onFocus={(e) => e.target.style.borderColor = 'var(--primary-color)'}
        onBlur={(e) => e.target.style.borderColor = 'var(--border-dark)'}
      />
    </div>
  );
}
