import { useState } from 'react';
import { initInstance } from '../lib/api';
import type { NetworkName, StorageMode } from '../lib/vault-types';
import { OtziWordmark } from '../App';

interface Props {
  onComplete: () => void;
}

export function InstallWizard({ onComplete }: Props) {
  const [step, setStep] = useState<1 | 2>(1);
  const [network, setNetwork] = useState<NetworkName>('testnet');
  const [storageMode, setStorageMode] = useState<StorageMode>('persistent');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleInit = async () => {
    if (storageMode === 'encrypted-persistent') {
      if (!password) { setError('Password required'); return; }
      if (password !== passwordConfirm) { setError('Passwords do not match'); return; }
    }
    setLoading(true);
    setError('');
    try {
      await initInstance(
        network,
        storageMode,
        storageMode === 'encrypted-persistent' ? password : undefined,
      );
      onComplete();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ceremony">
      <div style={{ textAlign: 'center', marginBottom: 8 }}>
        <OtziWordmark height={48} />
      </div>
      <p className="subtitle" style={{ textAlign: 'center' }}>First-time setup</p>

      <div className="steps">
        <div className={`step-dot ${step >= 1 ? 'active' : ''}`} />
        <div className={`step-dot ${step >= 2 ? 'active' : ''}`} />
      </div>

      {step === 1 && (
        <div className="card">
          <h2>Network</h2>
          <p>Select the OPNet network this instance will operate on.</p>
          <div className="form-row">
            <label>
              Network
              <select value={network} onChange={e => setNetwork(e.target.value as NetworkName)}>
                <option value="testnet">Testnet</option>
                <option value="mainnet">Mainnet</option>
              </select>
            </label>
          </div>
          <button className="btn btn-primary btn-full" onClick={() => setStep(2)}>
            Next
          </button>
        </div>
      )}

      {step === 2 && (
        <div className="card">
          <h2>Storage Mode</h2>
          <p>How should this instance store sensitive data (wallet keys, DKG shares)?</p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
            {([
              ['persistent', 'Persistent', 'Plaintext on server. Fast access, trusted environment.'],
              ['encrypted-persistent', 'Encrypted Persistent', 'Encrypted on server. Password required on each startup.'],
              ['encrypted-portable', 'Encrypted Portable', 'Download encrypted config file. Upload + password each session.'],
            ] as const).map(([value, label, desc]) => (
              <label
                key={value}
                style={{
                  display: 'flex', alignItems: 'flex-start', gap: 12, padding: 12,
                  background: storageMode === value ? 'var(--accent-dim)' : 'var(--bg-raised)',
                  borderRadius: 'var(--radius)', cursor: 'pointer',
                  border: storageMode === value ? '1px solid var(--accent)' : '1px solid rgba(237,239,242,0.06)',
                }}
              >
                <input
                  type="radio"
                  name="storageMode"
                  value={value}
                  checked={storageMode === value}
                  onChange={() => setStorageMode(value)}
                  style={{ marginTop: 4 }}
                />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{label}</div>
                  <div style={{ fontSize: 13, color: 'var(--white-dim)' }}>{desc}</div>
                </div>
              </label>
            ))}
          </div>

          {storageMode === 'encrypted-persistent' && (
            <div style={{ marginBottom: 16 }}>
              <div className="form-row">
                <label>
                  Password
                  <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Choose a strong password" />
                </label>
              </div>
              <div className="form-row">
                <label>
                  Confirm Password
                  <input type="password" value={passwordConfirm} onChange={e => setPasswordConfirm(e.target.value)} placeholder="Confirm password" />
                </label>
              </div>
            </div>
          )}

          {error && <div className="warning">{error}</div>}

          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn btn-secondary" onClick={() => setStep(1)}>Back</button>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleInit} disabled={loading}>
              {loading ? <span className="spinner" /> : 'Initialize'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
