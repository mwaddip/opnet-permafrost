import { useState } from 'react';

interface Props {
  partyId: number;
  onConfirm: (password: string) => void;
  onCancel: () => void;
}

export function PasswordModal({ partyId, onConfirm, onCancel }: Props) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');

  const valid = password.length >= 8 && password === confirm;

  return (
    <div className="modal-overlay" onClick={onCancel}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <h3>Encrypt Share for Party {partyId + 1}</h3>
        <p style={{ color: 'var(--white-dim)', fontSize: 13, marginBottom: 16 }}>
          Choose a strong password. If you lose this password, the share is
          unrecoverable.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <input
            type="password"
            placeholder="Password (min 8 characters)"
            value={password}
            onChange={e => setPassword(e.target.value)}
            autoFocus
          />
          <input
            type="password"
            placeholder="Confirm password"
            value={confirm}
            onChange={e => setConfirm(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && valid) onConfirm(password); }}
          />
        </div>
        {password.length > 0 && password.length < 8 && (
          <div className="warning" style={{ marginTop: 12, marginBottom: 0 }}>
            Password must be at least 8 characters.
          </div>
        )}
        {password.length >= 8 && confirm.length > 0 && password !== confirm && (
          <div className="warning" style={{ marginTop: 12, marginBottom: 0 }}>
            Passwords do not match.
          </div>
        )}
        <div className="modal-actions">
          <button className="btn btn-secondary" style={{ flex: 1 }} onClick={onCancel}>
            Cancel
          </button>
          <button
            className="btn btn-primary"
            style={{ flex: 1 }}
            disabled={!valid}
            onClick={() => onConfirm(password)}
          >
            Encrypt &amp; Download
          </button>
        </div>
      </div>
    </div>
  );
}
