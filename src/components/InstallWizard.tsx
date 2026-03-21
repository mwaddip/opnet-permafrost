import { useState } from 'react';
import { initInstance, setAdminToken, setSessionRole, restoreBackup } from '../lib/api';
import { toHex as bytesToHex, fromHex } from '../lib/hex';
import type { NetworkName, StorageMode } from '../lib/vault-types';
import { OtziWordmark } from '../App';

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  return fromHex(hex);
}

interface Props {
  onComplete: () => void;
}

export function InstallWizard({ onComplete }: Props) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [authMode, setAuthMode] = useState<'password' | 'wallet'>('password');
  // walletAddress is the ML-DSA identity: 0x + hex(SHA256(mldsaPubKey)) — NOT p2tr
  const [walletAddress, setWalletAddress] = useState('');
  const [walletConnecting, setWalletConnecting] = useState(false);
  const [network, setNetwork] = useState<NetworkName>('testnet');
  const [storageMode, setStorageMode] = useState<StorageMode>('persistent');
  const [password, setPassword] = useState('');
  const [passwordConfirm, setPasswordConfirm] = useState('');
  const [adminPassword, setAdminPassword] = useState('');
  const [adminPasswordConfirm, setAdminPasswordConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [restoreMode, setRestoreMode] = useState(false);
  const [restorePassword, setRestorePassword] = useState('');

  const handleConnectWallet = async () => {
    const wallet = (window as unknown as {
      opnet?: {
        requestAccounts(): Promise<string[]>;
        web3: { signMLDSAMessage(hex: string): Promise<{ signature: string; publicKey: string }> };
      };
    }).opnet;
    if (!wallet) { setError('OPWallet not detected. Install the OPWallet browser extension.'); return; }
    setWalletConnecting(true);
    setError('');
    try {
      await wallet.requestAccounts();
      // Sign a registration message to extract the ML-DSA public key
      const regMessage = 'PERMAFROST admin registration';
      const regBytes = new TextEncoder().encode(regMessage);
      const regHash = await crypto.subtle.digest('SHA-256', regBytes);
      const regHex = bytesToHex(new Uint8Array(regHash));
      const signed = await wallet.web3.signMLDSAMessage(regHex);
      const pubKeyBytes = hexToBytes(signed.publicKey);
      // walletAddress = 0x + hex(SHA256(mldsaPubKey)) — NOT p2tr/tweakedPubKey
      const hashBuf = await crypto.subtle.digest('SHA-256', pubKeyBytes.buffer as ArrayBuffer);
      const addr = '0x' + bytesToHex(new Uint8Array(hashBuf));
      setWalletAddress(addr);
    } catch (e) {
      setError((e as Error).message || 'Wallet connection rejected');
    } finally {
      setWalletConnecting(false);
    }
  };

  const handleInit = async () => {
    if (storageMode === 'encrypted-persistent') {
      if (!password) { setError('Encryption password required'); return; }
      if (password !== passwordConfirm) { setError('Encryption passwords do not match'); return; }
    }
    if (authMode === 'password') {
      if (!adminPassword) { setError('Admin password required'); return; }
      if (adminPassword !== adminPasswordConfirm) { setError('Admin passwords do not match'); return; }
    }
    setLoading(true);
    setError('');
    try {
      const result = await initInstance(
        network,
        storageMode,
        storageMode === 'encrypted-persistent' ? password : undefined,
        authMode === 'password' ? adminPassword : undefined,
        authMode,
        authMode === 'wallet' ? walletAddress : undefined,
        authMode === 'wallet' ? 'Admin' : undefined,
      );

      // If wallet mode, store the session token from init — no second sign needed
      if (result.token && result.role) {
        setAdminToken(result.token);
        setSessionRole(result.role);
      }

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
        <div className={`step-dot ${step >= 3 ? 'active' : ''}`} />
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

          <div style={{ textAlign: 'center', fontSize: 13, color: 'var(--gray-light)', margin: '16px 0 8px' }}>
            or
          </div>

          {!restoreMode ? (
            <button className="btn btn-secondary btn-full" onClick={() => setRestoreMode(true)}>
              Restore from Backup
            </button>
          ) : (
            <div style={{ padding: 12, background: 'var(--bg-raised)', borderRadius: 'var(--radius)', border: '1px solid var(--border-dim)' }}>
              <div className="form-row">
                <label>
                  Backup Password
                  <input type="password" autoFocus value={restorePassword}
                    onChange={e => setRestorePassword(e.target.value)}
                    placeholder="Password used when creating the backup" />
                </label>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn btn-primary" style={{ flex: 1 }} disabled={loading || !restorePassword} onClick={() => {
                  const input = document.createElement('input');
                  input.type = 'file';
                  input.accept = '.enc,.json';
                  input.onchange = async (e) => {
                    const file = (e.target as HTMLInputElement).files?.[0];
                    if (!file) return;
                    setLoading(true); setError('');
                    try {
                      const encrypted = await file.text();
                      await restoreBackup(encrypted, restorePassword);
                      onComplete();
                    } catch (err) { setError((err as Error).message); }
                    finally { setLoading(false); }
                  };
                  input.click();
                }}>
                  {loading ? <span className="spinner" /> : 'Select Backup File'}
                </button>
                <button className="btn btn-secondary" onClick={() => { setRestoreMode(false); setError(''); }}>Cancel</button>
              </div>
            </div>
          )}
        </div>
      )}

      {step === 2 && (
        <div className="card">
          <h2>Authentication</h2>
          <p>How should this instance control access?</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginBottom: 16 }}>
            {([
              ['password', 'Admin Password', 'Protect settings with a password. Simple setup.'],
              ['wallet', 'OPWallet (ML-DSA)', 'Authenticate with OPWallet signatures. Role-based access for multiple users.'],
            ] as const).map(([value, label, desc]) => (
              <label key={value} style={{
                display: 'flex', alignItems: 'flex-start', gap: 12, padding: 12,
                background: authMode === value ? 'var(--accent-dim)' : 'var(--bg-raised)',
                borderRadius: 'var(--radius)', cursor: 'pointer',
                border: authMode === value ? '1px solid var(--accent)' : '1px solid rgba(237,239,242,0.06)',
              }}>
                <input type="radio" name="authMode" value={value} checked={authMode === value}
                  onChange={() => { setAuthMode(value); setWalletAddress(''); setError(''); }} style={{ marginTop: 4 }} />
                <div>
                  <div style={{ fontWeight: 600, fontSize: 14 }}>{label}</div>
                  <div style={{ fontSize: 13, color: 'var(--white-dim)' }}>{desc}</div>
                </div>
              </label>
            ))}
          </div>

          {authMode === 'wallet' && !walletAddress && (
            <button className="btn btn-primary btn-full" onClick={handleConnectWallet} disabled={walletConnecting}>
              {walletConnecting ? <span className="spinner" /> : 'Connect & Sign with OPWallet'}
            </button>
          )}

          {authMode === 'wallet' && walletAddress && (
            <div style={{ padding: 12, background: 'var(--bg-raised)', borderRadius: 'var(--radius)', fontSize: 13 }}>
              <div style={{ color: 'var(--green)', marginBottom: 4 }}>Wallet verified</div>
              <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--white-dim)', wordBreak: 'break-all' }}>{walletAddress}</div>
              <div style={{ fontSize: 12, marginTop: 4 }}>This wallet will be the first admin.</div>
            </div>
          )}

          {error && <div className="warning" style={{ marginTop: 12 }}>{error}</div>}

          <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
            <button className="btn btn-secondary" onClick={() => setStep(1)}>Back</button>
            <button className="btn btn-primary" style={{ flex: 1 }}
              onClick={() => {
                setError('');
                if (authMode === 'wallet') {
                  // Wallet auth requires persistent server — skip storage selection
                  setStorageMode('persistent');
                  setStep(3);
                } else {
                  setStep(3);
                }
              }}
              disabled={authMode === 'wallet' && !walletAddress}>
              Next
            </button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="card">
          {authMode !== 'wallet' && (
            <>
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
                  Encryption Password
                  <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Choose a strong password" />
                </label>
              </div>
              <div className="form-row">
                <label>
                  Confirm Encryption Password
                  <input type="password" value={passwordConfirm} onChange={e => setPasswordConfirm(e.target.value)} placeholder="Confirm password" />
                </label>
              </div>
            </div>
          )}
            </>
          )}

          {authMode === 'password' && (
            <div style={{ marginBottom: 16 }}>
              <p style={{ fontSize: 13, color: 'var(--white-dim)', marginBottom: 8 }}>
                Admin password protects settings changes, contract management, and transaction broadcasting.
              </p>
              <div className="form-row">
                <label>
                  Admin Password
                  <input type="password" value={adminPassword} onChange={e => setAdminPassword(e.target.value)} placeholder="Choose an admin password" />
                </label>
              </div>
              <div className="form-row">
                <label>
                  Confirm Admin Password
                  <input type="password" value={adminPasswordConfirm} onChange={e => setAdminPasswordConfirm(e.target.value)} placeholder="Confirm admin password" />
                </label>
              </div>
            </div>
          )}

          {error && <div className="warning">{error}</div>}

          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn btn-secondary" onClick={() => setStep(2)}>Back</button>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleInit} disabled={loading}>
              {loading ? <span className="spinner" /> : 'Initialize'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
