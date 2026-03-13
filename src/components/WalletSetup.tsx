import { useState } from 'react';
import { generateWallet, skipWallet } from '../lib/api';
import { OtziWordmark } from '../App';

interface Props {
  onComplete: () => void;
}

export function WalletSetup({ onComplete }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [mnemonic, setMnemonic] = useState<string | null>(null);
  const [p2tr, setP2tr] = useState<string | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [dontShow, setDontShow] = useState(false);

  const handleGenerate = async () => {
    setLoading(true);
    setError('');
    try {
      const result = await generateWallet();
      setP2tr(result.config.wallet?.p2tr ?? null);
      setMnemonic(result.mnemonic);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const handleSkip = async () => {
    setLoading(true);
    try {
      await skipWallet(dontShow);
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
      <p className="subtitle" style={{ textAlign: 'center' }}>Wallet Setup</p>

      {!mnemonic ? (
        <div className="card">
          <h2>Generate BTC Wallet</h2>
          <p>
            Generate a BTC keypair for this instance. This wallet will be used to fund
            and broadcast OPNet transactions. The ML-DSA key for signing comes from the
            DKG ceremony (next step).
          </p>
          <p>
            If you skip this, the signing page will display signatures for manual copying
            but cannot broadcast transactions.
          </p>

          {error && <div className="warning">{error}</div>}

          <button className="btn btn-primary btn-full" onClick={handleGenerate} disabled={loading} style={{ marginBottom: 12 }}>
            {loading ? <span className="spinner" /> : 'Generate Wallet'}
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
            <input
              type="checkbox"
              id="dontShow"
              checked={dontShow}
              onChange={e => setDontShow(e.target.checked)}
            />
            <label htmlFor="dontShow" style={{ fontSize: 13, color: 'var(--white-dim)', cursor: 'pointer' }}>
              Don't show this again
            </label>
          </div>

          <button className="btn btn-secondary btn-full" onClick={handleSkip} disabled={loading}>
            Skip for now
          </button>
        </div>
      ) : (
        <div className="card">
          <h2>Backup Your Mnemonic</h2>
          <div className="warning">
            Write down these words and store them securely. This is the ONLY time they will be shown.
          </div>
          <div className="pubkey-display" style={{ fontSize: 15, lineHeight: 1.8 }}>
            {mnemonic}
          </div>
          {p2tr && (
            <>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>P2TR Address</h3>
              <div className="pubkey-display">{p2tr}</div>
              <p>Fund this address with BTC to pay for transaction fees.</p>
            </>
          )}
          <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16, cursor: 'pointer' }}>
            <input type="checkbox" checked={confirmed} onChange={e => setConfirmed(e.target.checked)} />
            <span style={{ fontSize: 13 }}>I have written down and securely stored my mnemonic</span>
          </label>
          <button className="btn btn-primary btn-full" onClick={onComplete} disabled={!confirmed}>
            Continue to DKG Ceremony
          </button>
        </div>
      )}
    </div>
  );
}
