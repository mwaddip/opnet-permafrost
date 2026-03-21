import { useState, useCallback } from 'react';
import { getChallenge, verifyAuth, redeemInvite, setAdminToken, setSessionRole } from '../lib/api';
import { toHex as bytesToHex, fromHex, uint8ToBase64 } from '../lib/hex';
import { OtziWordmark } from '../App';

interface OPNetWallet {
  requestAccounts(): Promise<string[]>;
  web3: {
    signMLDSAMessage(messageHex: string): Promise<{ signature: string; publicKey: string }>;
  };
}

declare global {
  interface Window {
    opnet?: OPNetWallet;
  }
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  return fromHex(hex);
}

interface Props {
  onAuthenticated: (role: string, address: string, sessionCode?: string) => void;
}

export function WalletAuth({ onAuthenticated }: Props) {
  const [step, setStep] = useState<'connect' | 'signing' | 'invite'>('connect');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [walletAddress, setWalletAddress] = useState('');
  const [sessionCode, setSessionCode] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [inviteLabel, setInviteLabel] = useState('');

  const signChallenge = useCallback(async () => {
    const wallet = window.opnet;
    if (!wallet) {
      setError('OPWallet not detected. Install the OPWallet browser extension.');
      return null;
    }

    const { challenge } = await getChallenge();

    const message = `PERMAFROST auth ${challenge}`;
    const msgBytes = new TextEncoder().encode(message);
    const hashBuf = await crypto.subtle.digest('SHA-256', msgBytes);
    const messageHex = bytesToHex(new Uint8Array(hashBuf));

    const signed = await wallet.web3.signMLDSAMessage(messageHex);

    const signature = uint8ToBase64(hexToBytes(signed.signature));
    const publicKey = uint8ToBase64(hexToBytes(signed.publicKey));

    return { challenge, signature, publicKey };
  }, []);

  const handleConnect = async () => {
    setError('');
    setLoading(true);
    try {
      const wallet = window.opnet;
      if (!wallet) {
        setError('OPWallet not detected. Install the OPWallet browser extension.');
        return;
      }

      const accounts = await wallet.requestAccounts();
      if (!accounts?.length) { setError('No accounts returned'); return; }
      setWalletAddress(accounts[0]!);
      setStep('signing');

      const auth = await signChallenge();
      if (!auth) return;

      // Pass session code to auto-register as user if not in DB
      const code = sessionCode.trim().toUpperCase() || undefined;
      const result = await verifyAuth(auth.challenge, auth.signature, auth.publicKey, code);

      if (result.authenticated && result.token && result.role) {
        setAdminToken(result.token);
        setSessionRole(result.role);
        onAuthenticated(result.role, result.address || '', code);
      } else if (result.needsInvite) {
        setStep('invite');
      } else {
        setError('Authentication failed');
        setStep('connect');
      }
    } catch (e) {
      setError((e as Error).message);
      setStep('connect');
    } finally {
      setLoading(false);
    }
  };

  const handleRedeem = async () => {
    if (!inviteCode) return;
    setError('');
    setLoading(true);
    try {
      const auth = await signChallenge();
      if (!auth) return;

      const result = await redeemInvite(
        auth.challenge, auth.signature, auth.publicKey,
        inviteCode, inviteLabel || undefined,
      );

      if (result.authenticated && result.token && result.role) {
        setAdminToken(result.token);
        setSessionRole(result.role);
        onAuthenticated(result.role, result.address || '');
      } else {
        setError('Invalid, expired, or exhausted invite code');
      }
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

      {step === 'connect' && (
        <div className="card">
          <p style={{ textAlign: 'center', marginBottom: 16 }}>Connect your OPWallet to authenticate</p>

          <div className="form-row">
            <label>
              Session Code
              <input
                autoFocus
                value={sessionCode}
                onChange={e => {
                  const val = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
                  setSessionCode(val);
                  // Session code = temporary access token — skip wallet auth entirely
                  if (val.length >= 6) {
                    onAuthenticated('', '', val);
                  }
                }}
                placeholder="Paste session code to join ceremony"
                maxLength={6}
                style={{ fontFamily: 'monospace', fontSize: 18, letterSpacing: '0.15em', textTransform: 'uppercase', textAlign: 'center' }}
              />
            </label>
          </div>

          <p style={{ fontSize: 11, color: 'var(--white-dim)', textAlign: 'center', marginBottom: 16 }}>
            {sessionCode
              ? 'Connect wallet to join as signer'
              : 'Optional — paste a code if joining a DKG ceremony'}
          </p>

          {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}
          <button className="btn btn-primary btn-full" onClick={handleConnect} disabled={loading}>
            {loading ? <span className="spinner" /> : 'Connect OPWallet'}
          </button>
        </div>
      )}

      {step === 'signing' && (
        <div className="card" style={{ textAlign: 'center' }}>
          <div className="spinner" style={{ margin: '0 auto 16px' }} />
          <p>Signing challenge with OPWallet...</p>
          <p style={{ fontSize: 12, color: 'var(--white-dim)', fontFamily: 'monospace' }}>{walletAddress}</p>
        </div>
      )}

      {step === 'invite' && (
        <div className="card">
          <h2>Invite Code Required</h2>
          <p style={{ fontSize: 13, color: 'var(--white-dim)', marginBottom: 16 }}>
            Your wallet is not registered. Enter an invite code to gain access.
          </p>
          <div className="form-row">
            <label>
              Invite Code
              <input
                autoFocus
                value={inviteCode}
                onChange={e => setInviteCode(e.target.value.toUpperCase())}
                placeholder="e.g. X7K2M9"
                style={{ fontFamily: 'monospace', textTransform: 'uppercase' }}
              />
            </label>
          </div>
          <div className="form-row">
            <label>
              Display Name (optional)
              <input
                value={inviteLabel}
                onChange={e => setInviteLabel(e.target.value)}
                placeholder="Your name"
              />
            </label>
          </div>
          {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}
          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn btn-secondary" onClick={() => { setStep('connect'); setError(''); }}>Back</button>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleRedeem} disabled={loading || !inviteCode}>
              {loading ? <span className="spinner" /> : 'Submit'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
