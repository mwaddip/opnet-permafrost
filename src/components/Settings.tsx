import { useState, useEffect } from 'react';
import { getConfig, getWalletBalance, getBalances, resetInstance, updateContracts, updateHosting, removeHosting, adminUnlock, setAdminToken, clearAdminToken, hasAdminToken } from '../lib/api';
import { OP20_METHODS } from '../lib/op20-methods';
import type { VaultConfig, ContractConfig } from '../lib/vault-types';
import type { SendPrefill } from '../App';

interface Props {
  onBack: () => void;
  onSend: (prefill: SendPrefill) => void;
}

function formatTokenBalance(raw: string, decimals: number): string {
  if (decimals === 0) return raw;
  const bi = BigInt(raw);
  const divisor = 10n ** BigInt(decimals);
  const whole = bi / divisor;
  const remainder = bi % divisor;
  if (remainder === 0n) return whole.toString();
  const fracStr = remainder.toString().padStart(decimals, '0').replace(/0+$/, '');
  return `${whole}.${fracStr}`;
}

async function deriveOpnetIdentity(combinedPubKeyHex: string): Promise<string> {
  const bytes = new Uint8Array(combinedPubKeyHex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
  const hash = await crypto.subtle.digest('SHA-256', bytes.buffer as ArrayBuffer);
  return '0x' + Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function Settings({ onBack, onSend }: Props) {
  const [config, setConfig] = useState<VaultConfig | null>(null);
  const [balance, setBalance] = useState<string>('0');
  const [tokenBalances, setTokenBalances] = useState<Array<{ address: string; symbol: string; balance: string; decimals: number }>>([]);
  const [opnetIdentity, setOpnetIdentity] = useState<string | null>(null);
  const [resetStep, setResetStep] = useState<0 | 1 | 2>(0);
  const [resetInput, setResetInput] = useState('');
  const [error, setError] = useState('');
  const [unlocked, setUnlocked] = useState(hasAdminToken());
  const [unlockPassword, setUnlockPassword] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [unlocking, setUnlocking] = useState(false);
  const [showUnlockInput, setShowUnlockInput] = useState(false);

  const needsAdmin = config?.hasAdminPassword ?? false;
  const isLocked = needsAdmin && !unlocked;

  const handleUnlock = async () => {
    if (!unlockPassword) return;
    setUnlocking(true);
    setUnlockError('');
    try {
      const { token } = await adminUnlock(unlockPassword);
      setAdminToken(token);
      setUnlocked(true);
      setShowUnlockInput(false);
      setUnlockPassword('');
    } catch (e) {
      setUnlockError((e as Error).message);
    } finally {
      setUnlocking(false);
    }
  };

  const handleLock = () => {
    clearAdminToken();
    setUnlocked(false);
  };

  useEffect(() => {
    getConfig().then(c => {
      setConfig(c);
      if (c.permafrost?.combinedPubKey) {
        deriveOpnetIdentity(c.permafrost.combinedPubKey).then(setOpnetIdentity).catch(() => {});
      }
    }).catch(console.error);
    getWalletBalance().then(r => setBalance(r.balance)).catch(() => {});
    getBalances().then(r => setTokenBalances(r.balances.map(b => ({ address: b.address, symbol: b.symbol, balance: b.balance, decimals: b.decimals })))).catch(() => {});
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
        <div style={{ display: 'flex', gap: 8 }}>
          {needsAdmin && unlocked && (
            <button className="btn btn-secondary" onClick={handleLock} style={{ fontSize: 13 }}>Lock</button>
          )}
          <button className="btn btn-secondary" onClick={onBack}>Back</button>
        </div>
      </div>

      {/* Admin unlock bar */}
      {isLocked && (
        <div className="card" style={{ marginBottom: 16, borderColor: 'var(--accent)' }}>
          {!showUnlockInput ? (
            <button className="btn btn-primary btn-full" onClick={() => setShowUnlockInput(true)}>
              Unlock Settings
            </button>
          ) : (
            <>
              <div style={{ display: 'flex', gap: 8 }}>
                <input
                  type="password"
                  autoFocus
                  value={unlockPassword}
                  onChange={e => { setUnlockPassword(e.target.value); setUnlockError(''); }}
                  onKeyDown={e => e.key === 'Enter' && handleUnlock()}
                  placeholder="Admin password"
                  style={{ flex: 1 }}
                />
                <button className="btn btn-primary" onClick={handleUnlock} disabled={unlocking || !unlockPassword}>
                  {unlocking ? <span className="spinner" /> : 'Unlock'}
                </button>
                <button className="btn btn-secondary" onClick={() => { setShowUnlockInput(false); setUnlockPassword(''); setUnlockError(''); }}>
                  Cancel
                </button>
              </div>
              {unlockError && <div className="warning" style={{ marginTop: 8 }}>{unlockError}</div>}
            </>
          )}
        </div>
      )}

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
          {opnetIdentity && (
            <div style={{ marginTop: 8 }}>
              <strong style={{ fontSize: 13, color: 'var(--gray-light)' }}>OPNet Identity</strong>
              <div className="pubkey-display" style={{ fontSize: 12, marginTop: 4 }}>{opnetIdentity}</div>
            </div>
          )}
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
            <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', fontSize: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span>{t.symbol}</span>
                <button
                  style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 14, padding: 0, lineHeight: 1 }}
                  onClick={() => onSend({ contractAddress: t.address, method: 'transfer' })}
                  title="Send"
                >
                  ↗
                </button>
              </div>
              <span style={{ fontFamily: 'monospace' }}>{formatTokenBalance(t.balance, t.decimals)}</span>
            </div>
          ))}
        </div>
      )}

      {/* Hosting */}
      <HostingManager config={config} onConfigUpdate={setConfig} disabled={isLocked} />

      {/* Contracts */}
      <ContractManager
        contracts={config.contracts}
        disabled={isLocked}
        onUpdate={(contracts) => {
          updateContracts(contracts).then(() => {
            setConfig(prev => prev ? { ...prev, contracts } : prev);
          }).catch(e => setError((e as Error).message));
        }}
      />

      {/* Reset */}
      <div className="card" style={isLocked ? { opacity: 0.5, pointerEvents: 'none' } : {}}>
        <h2>Reset Instance</h2>
        {resetStep === 0 && (
          <button className="btn btn-secondary btn-full" style={{ color: 'var(--red)' }} onClick={handleReset} disabled={isLocked}>
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

// ── Hosting Manager ──

function HostingManager({ config, onConfigUpdate, disabled }: { config: VaultConfig; onConfigUpdate: (c: VaultConfig) => void; disabled?: boolean }) {
  const hosting = config.hosting;
  const [domain, setDomain] = useState(hosting?.domain || '');
  const [httpsEnabled, setHttpsEnabled] = useState(hosting?.httpsEnabled || false);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const hasChanges = domain !== (hosting?.domain || '') || httpsEnabled !== (hosting?.httpsEnabled || false);

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setMessage('');
    try {
      const result = await updateHosting(domain, httpsEnabled);
      onConfigUpdate(result.config);
      if (result.warning) {
        setMessage(result.warning);
      } else {
        setMessage(httpsEnabled ? 'Domain configured with HTTPS. Certificate provisioning started.' : 'Domain configured.');
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    setSaving(true);
    setError('');
    setMessage('');
    try {
      await removeHosting();
      setDomain('');
      setHttpsEnabled(false);
      onConfigUpdate({ ...config, hosting: undefined });
      setMessage('Hosting configuration removed.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="card" style={disabled ? { opacity: 0.5, pointerEvents: 'none' } : {}}>
      <h2>Hosting</h2>
      <p style={{ fontSize: 13, color: 'var(--white-dim)', marginBottom: 16 }}>
        Configure a domain for external access. HTTPS uses Let's Encrypt automatic certificates via Caddy.
      </p>

      <div className="form-row">
        <label>
          Domain
          <input
            value={domain}
            onChange={e => setDomain(e.target.value)}
            placeholder="e.g. vault.example.com"
          />
        </label>
      </div>

      <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, cursor: 'pointer', marginBottom: 16 }}>
        <input
          type="checkbox"
          checked={httpsEnabled}
          onChange={e => setHttpsEnabled(e.target.checked)}
          disabled={!domain.trim()}
        />
        Enable HTTPS (Let's Encrypt)
      </label>

      {httpsEnabled && domain.trim() && (
        <div style={{ fontSize: 12, color: 'var(--white-dim)', marginBottom: 16, padding: '8px 12px', background: 'var(--gray-dark)', borderRadius: 6 }}>
          Ports 80 and 443 must be publicly reachable for certificate issuance. DNS for <strong>{domain}</strong> must point to this server.
        </div>
      )}

      {hosting?.httpsStatus === 'active' && (
        <div style={{ fontSize: 13, color: 'var(--green)', marginBottom: 12 }}>HTTPS active</div>
      )}
      {hosting?.httpsStatus === 'error' && (
        <div className="warning" style={{ marginBottom: 12 }}>{hosting.httpsError || 'Certificate error'}</div>
      )}

      {error && <div className="warning" style={{ marginBottom: 12 }}>{error}</div>}
      {message && <div style={{ fontSize: 13, color: 'var(--accent)', marginBottom: 12 }}>{message}</div>}

      <div style={{ display: 'flex', gap: 12 }}>
        <button
          className="btn btn-primary"
          style={{ flex: 1 }}
          onClick={handleSave}
          disabled={saving || !hasChanges}
        >
          {saving ? <span className="spinner" /> : 'Save'}
        </button>
        {hosting && (
          <button
            className="btn btn-secondary"
            onClick={handleRemove}
            disabled={saving}
          >
            Remove
          </button>
        )}
      </div>
    </div>
  );
}

// ── Contract Manager ──

type ContractType = 'op20' | 'custom';

function ContractManager({ contracts, onUpdate, disabled }: { contracts: ContractConfig[]; onUpdate: (c: ContractConfig[]) => void; disabled?: boolean }) {
  const [adding, setAdding] = useState(false);
  const [contractType, setContractType] = useState<ContractType>('op20');
  const [name, setName] = useState('');
  const [address, setAddress] = useState('');
  const [selectedMethods, setSelectedMethods] = useState<Set<string>>(new Set());
  const [abiText, setAbiText] = useState('');
  const [abiError, setAbiError] = useState('');
  const [parsedAbiMethods, setParsedAbiMethods] = useState<string[]>([]);

  const resetForm = () => {
    setAdding(false);
    setContractType('op20');
    setName('');
    setAddress('');
    setSelectedMethods(new Set());
    setAbiText('');
    setAbiError('');
    setParsedAbiMethods([]);
  };

  const handleParseAbi = () => {
    try {
      const abi = JSON.parse(abiText) as Array<{ name?: string; inputs?: unknown[] }>;
      const methodNames = abi.filter(e => e.name && e.inputs).map(e => e.name!);
      if (methodNames.length === 0) { setAbiError('No callable methods found in ABI'); return; }
      setParsedAbiMethods(methodNames);
      setSelectedMethods(new Set(methodNames));
      setAbiError('');
    } catch {
      setAbiError('Invalid JSON');
    }
  };

  const toggleMethod = (m: string) => {
    setSelectedMethods(prev => {
      const next = new Set(prev);
      if (next.has(m)) next.delete(m); else next.add(m);
      return next;
    });
  };

  const handleAdd = () => {
    if (!name.trim() || !address.trim()) return;
    if (selectedMethods.size === 0) return;

    const newContract: ContractConfig = {
      name: name.trim(),
      address: address.trim(),
      methods: [...selectedMethods],
      abi: contractType === 'custom' ? JSON.parse(abiText) : [],
    };
    onUpdate([...contracts, newContract]);
    resetForm();
  };

  const handleRemove = (index: number) => {
    onUpdate(contracts.filter((_, i) => i !== index));
  };

  const availableMethods = contractType === 'op20'
    ? OP20_METHODS.map(m => m.name)
    : parsedAbiMethods;

  return (
    <div className="card" style={disabled ? { opacity: 0.5, pointerEvents: 'none' } : {}}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ marginBottom: 0 }}>Contracts</h2>
        {!adding && (
          <button className="btn btn-secondary" style={{ fontSize: 13, padding: '6px 14px' }} onClick={() => setAdding(true)}>
            + Add Contract
          </button>
        )}
      </div>

      {/* Existing contracts */}
      {contracts.length === 0 && !adding && (
        <p style={{ color: 'var(--white-dim)', fontSize: 13 }}>
          No contracts configured. The signing page will show all OP-20 methods with manual address entry.
        </p>
      )}
      {contracts.map((c, i) => (
        <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', padding: '10px 0', borderBottom: '1px solid var(--gray-dark)' }}>
          <div>
            <strong style={{ fontSize: 14 }}>{c.name}</strong>
            {c.abi && c.abi.length > 0 && <span style={{ fontSize: 11, color: 'var(--accent)', marginLeft: 8 }}>Custom ABI</span>}
            <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--white-dim)', marginTop: 2 }}>{c.address}</div>
            <div style={{ fontSize: 12, color: 'var(--gray-light)', marginTop: 2 }}>{c.methods.join(', ')}</div>
          </div>
          <button
            className="btn btn-secondary"
            style={{ fontSize: 12, padding: '4px 10px', color: 'var(--red)', flexShrink: 0 }}
            onClick={() => handleRemove(i)}
          >
            Remove
          </button>
        </div>
      ))}

      {/* Add contract form */}
      {adding && (
        <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--gray-dark)' }}>
          <h3 style={{ fontSize: 15, marginBottom: 12 }}>Add Contract</h3>

          {/* Type selector */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <button
              className={`btn ${contractType === 'op20' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ flex: 1, padding: '8px 12px', fontSize: 13 }}
              onClick={() => { setContractType('op20'); setSelectedMethods(new Set()); setParsedAbiMethods([]); setAbiText(''); }}
            >
              Standard OP-20
            </button>
            <button
              className={`btn ${contractType === 'custom' ? 'btn-primary' : 'btn-secondary'}`}
              style={{ flex: 1, padding: '8px 12px', fontSize: 13 }}
              onClick={() => { setContractType('custom'); setSelectedMethods(new Set()); }}
            >
              Custom ABI
            </button>
          </div>

          <div className="form-row">
            <label>
              Name
              <input value={name} onChange={e => setName(e.target.value)} placeholder="e.g. WBTC Token" />
            </label>
          </div>
          <div className="form-row">
            <label>
              Contract Address
              <input value={address} onChange={e => setAddress(e.target.value)} placeholder="0x..." />
            </label>
          </div>

          {/* Custom ABI input */}
          {contractType === 'custom' && (
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 13, color: 'var(--gray-light)', marginBottom: 6 }}>ABI (required)</label>
              <textarea
                className="blob-textarea"
                value={abiText}
                onChange={e => setAbiText(e.target.value)}
                placeholder="Paste ABI JSON array..."
                rows={4}
              />
              {abiError && <div className="warning" style={{ marginTop: 8 }}>{abiError}</div>}
              <button className="btn btn-secondary" style={{ marginTop: 8, fontSize: 13 }} onClick={handleParseAbi}>
                Parse ABI
              </button>
            </div>
          )}

          {/* Method selection */}
          {availableMethods.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 13, color: 'var(--gray-light)', marginBottom: 8 }}>Methods</label>
              <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
                <button className="btn btn-secondary" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => setSelectedMethods(new Set(availableMethods))}>
                  Select All
                </button>
                <button className="btn btn-secondary" style={{ fontSize: 11, padding: '3px 8px' }} onClick={() => setSelectedMethods(new Set())}>
                  Clear
                </button>
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {availableMethods.map(m => (
                  <label key={m} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, cursor: 'pointer', padding: '4px 8px', borderRadius: 6, background: selectedMethods.has(m) ? 'var(--gray-dark)' : 'transparent' }}>
                    <input type="checkbox" checked={selectedMethods.has(m)} onChange={() => toggleMethod(m)} />
                    {m}
                  </label>
                ))}
              </div>
            </div>
          )}

          <div style={{ display: 'flex', gap: 12 }}>
            <button className="btn btn-secondary" style={{ flex: 1 }} onClick={resetForm}>Cancel</button>
            <button
              className="btn btn-primary"
              style={{ flex: 1 }}
              onClick={handleAdd}
              disabled={!name.trim() || !address.trim() || selectedMethods.size === 0 || (contractType === 'custom' && parsedAbiMethods.length === 0)}
            >
              Add
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
