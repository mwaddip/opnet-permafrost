import { useState, useEffect } from 'react';
import { getConfig, getWalletBalance, getBalances, resetInstance, updateContracts } from '../lib/api';
import type { VaultConfig, ContractConfig } from '../lib/vault-types';

interface Props {
  onBack: () => void;
}

export function Settings({ onBack }: Props) {
  const [config, setConfig] = useState<VaultConfig | null>(null);
  const [balance, setBalance] = useState<string>('0');
  const [tokenBalances, setTokenBalances] = useState<Array<{ symbol: string; balance: string }>>([]);
  const [resetStep, setResetStep] = useState<0 | 1 | 2>(0);
  const [resetInput, setResetInput] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    getConfig().then(setConfig).catch(console.error);
    getWalletBalance().then(r => setBalance(r.balance)).catch(() => {});
    getBalances().then(r => setTokenBalances(r.balances.map(b => ({ symbol: b.symbol, balance: b.balance })))).catch(() => {});
  }, []);

  const handleReset = async () => {
    if (resetStep === 0) { setResetStep(1); return; }
    if (resetStep === 1) { setResetStep(2); return; }
    if (resetInput !== 'RESET') { setError('Type RESET to confirm'); return; }
    try {
      await resetInstance();
      window.location.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  if (!config) return <div className="ceremony"><div className="spinner" /></div>;

  return (
    <div className="ceremony" style={{ maxWidth: 720 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <h1>Settings</h1>
        <button className="btn btn-secondary" onClick={onBack}>Back</button>
      </div>

      {/* Network */}
      <div className="card">
        <h2>Network</h2>
        <p>{config.network === 'testnet' ? 'Testnet' : 'Mainnet'} · Storage: {config.storageMode}</p>
      </div>

      {/* Wallet */}
      <div className="card">
        <h2>Wallet</h2>
        {config.wallet ? (
          <>
            <div style={{ marginBottom: 8 }}>
              <strong style={{ fontSize: 13, color: 'var(--gray-light)' }}>P2TR Address</strong>
              <div className="pubkey-display" style={{ fontSize: 12, marginTop: 4 }}>{config.wallet.p2tr}</div>
            </div>
            <div style={{ marginBottom: 8 }}>
              <strong style={{ fontSize: 13, color: 'var(--gray-light)' }}>Tweaked Public Key</strong>
              <div className="pubkey-display" style={{ fontSize: 12, marginTop: 4 }}>{config.wallet.tweakedPubKey}</div>
            </div>
            <div>
              <strong style={{ fontSize: 13, color: 'var(--gray-light)' }}>BTC Balance</strong>
              <div style={{ fontSize: 16, fontWeight: 600, marginTop: 4 }}>{(parseInt(balance) / 1e8).toFixed(8)} BTC</div>
            </div>
          </>
        ) : (
          <p>No wallet configured. Signatures are display-only.</p>
        )}
      </div>

      {/* Permafrost */}
      {config.permafrost && (
        <div className="card">
          <h2>Permafrost</h2>
          <p>{config.permafrost.threshold}-of-{config.permafrost.parties} threshold · Security level {config.permafrost.level}</p>
          <div style={{ marginTop: 8 }}>
            <strong style={{ fontSize: 13, color: 'var(--gray-light)' }}>Combined ML-DSA Public Key</strong>
            <div className="pubkey-display" style={{ fontSize: 11, marginTop: 4 }}>
              {config.permafrost.combinedPubKey.slice(0, 64)}...
            </div>
          </div>
        </div>
      )}

      {/* OP-20 Balances */}
      {tokenBalances.length > 0 && (
        <div className="card">
          <h2>Token Balances</h2>
          {tokenBalances.map((t, i) => (
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', fontSize: 14 }}>
              <span>{t.symbol}</span>
              <span style={{ fontFamily: 'monospace' }}>{t.balance}</span>
            </div>
          ))}
        </div>
      )}

      {/* Contracts */}
      <div className="card">
        <h2>Configured Contracts</h2>
        {config.contracts.length === 0 ? (
          <p>No contracts configured. All OP-20 methods available for any contract.</p>
        ) : (
          config.contracts.map((c, i) => (
            <div key={i} style={{ marginBottom: 8 }}>
              <strong style={{ fontSize: 14 }}>{c.name || 'Unnamed'}</strong>
              <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--white-dim)' }}>{c.address}</div>
              <div style={{ fontSize: 12, color: 'var(--gray-light)' }}>Methods: {c.methods.join(', ')}</div>
            </div>
          ))
        )}
      </div>

      {/* Reset */}
      <div className="card">
        <h2>Reset Instance</h2>
        {resetStep === 0 && (
          <button className="btn btn-secondary btn-full" style={{ color: 'var(--red)' }} onClick={handleReset}>
            Reset Instance
          </button>
        )}
        {resetStep === 1 && (
          <>
            <div className="warning">This will permanently delete all data: wallet, DKG shares, and configuration.</div>
            <div style={{ display: 'flex', gap: 12 }}>
              <button className="btn btn-secondary" onClick={() => setResetStep(0)}>Cancel</button>
              <button className="btn btn-secondary" style={{ color: 'var(--red)', flex: 1 }} onClick={handleReset}>
                I understand, continue
              </button>
            </div>
          </>
        )}
        {resetStep === 2 && (
          <>
            <div className="warning">Type RESET to confirm.</div>
            <input
              value={resetInput}
              onChange={e => setResetInput(e.target.value)}
              placeholder="Type RESET"
              style={{ width: '100%', marginBottom: 12 }}
            />
            {error && <div className="warning">{error}</div>}
            <div style={{ display: 'flex', gap: 12 }}>
              <button className="btn btn-secondary" onClick={() => { setResetStep(0); setResetInput(''); }}>Cancel</button>
              <button className="btn btn-secondary" style={{ color: 'var(--red)', flex: 1 }} onClick={handleReset}>
                Confirm Reset
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
