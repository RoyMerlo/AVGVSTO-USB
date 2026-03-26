import React from 'react';

export function Button({ children, onClick, variant = 'primary', className = '', type = 'button', disabled = false }) {
  const baseStyle = {
    padding: '0.75rem 1.5rem',
    borderRadius: '4px',
    fontWeight: '600',
    fontSize: '1rem',
    cursor: disabled ? 'not-allowed' : 'pointer',
    border: 'none',
    transition: 'all 0.2s ease',
    textTransform: 'uppercase',
    letterSpacing: '0.05em',
    opacity: disabled ? 0.5 : 1,
  };

  const variants = {
    primary: {
      backgroundColor: 'var(--primary-color)',
      color: '#000',
    },
    secondary: {
      backgroundColor: 'transparent',
      color: 'var(--text-primary)',
      border: '1px solid var(--border-dark)',
    },
    danger: {
      backgroundColor: '#ef4444',
      color: '#fff',
    }
  };

  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={className}
      style={{ ...baseStyle, ...variants[variant] }}
    >
      {children}
    </button>
  );
}
