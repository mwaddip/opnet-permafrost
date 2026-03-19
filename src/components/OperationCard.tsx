import { useState } from 'react';
import { encodeTx } from '../lib/api';
import type { ManifestOperation, ManifestConfig } from '../lib/manifest-types';
import { resolveParamValue, encodeParamValue, resolveAbi } from '../lib/manifest';

interface Props {
  operation: ManifestOperation;
  config: ManifestConfig;
  reads: Record<string, unknown>;
  onExecute: (contractAddress: string, method: string, params: string[], paramTypes: Array<'address' | 'u256' | 'bytes'>, messageHash: string, message: Uint8Array, abi?: unknown[]) => void;
  disabled?: boolean;
}

export function OperationCard({ operation, config, reads, onExecute, disabled }: Props) {
  const [values, setValues] = useState<Record<string, string>>(() => {
    const initial: Record<string, string> = {};
    for (const p of operation.params) {
      const resolved = resolveParamValue(p, config, reads);
      if (resolved) initial[p.name] = resolved;
    }
    return initial;
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [confirming, setConfirming] = useState(false);

  const contractAddress = operation.contract === '$dynamic'
    ? values['$contract'] || ''
    : config.addresses[operation.contract] || '';

  const handleExecute = async () => {
    if (operation.confirm && !confirming) {
      setConfirming(true);
      return;
    }
    setConfirming(false);
    setError('');
    setLoading(true);

    try {
      const params: string[] = [];
      const paramTypes: Array<'address' | 'u256' | 'bytes'> = [];

      for (const p of operation.params) {
        if (p.name === '$contract') continue;
        const raw = values[p.name] || '';
        if (!raw && !p.source) { setError(`${p.label || p.name} is required`); setLoading(false); return; }
        const encoded = encodeParamValue(raw, p);
        params.push(encoded);
        const mappedType = p.type === 'uint256' ? 'u256' : p.type === 'bool' ? 'u256' : p.type as 'address' | 'bytes';
        if (p.type === 'bool') params[params.length - 1] = raw === 'true' || raw === '1' ? '1' : '0';
        paramTypes.push(mappedType);
      }

      const result = await encodeTx(operation.method, params, paramTypes);
      const msgBytes = new Uint8Array(result.calldata.match(/.{2}/g)!.map(b => parseInt(b, 16)));
      // Resolve the ABI for the contract so broadcast can find the method
      const contractKey = operation.contract === '$dynamic' ? undefined : operation.contract;
      const rawAbi = contractKey ? config.manifest.contracts[contractKey]?.abi : undefined;
      const abi = rawAbi ? resolveAbi(rawAbi) : undefined;
      onExecute(contractAddress, operation.method, params, paramTypes, result.messageHash, msgBytes, abi);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card" style={{ marginBottom: 12 }}>
      <h3 style={{ fontSize: 15, marginBottom: 4 }}>{operation.label}</h3>
      {operation.description && (
        <p style={{ fontSize: 12, color: 'var(--white-dim)', marginBottom: 12 }}>{operation.description}</p>
      )}

      {operation.params.map(p => {
        if (p.name === '$contract') {
          return (
            <div className="form-row" key={p.name}>
              <label>
                {p.label || 'Contract'}
                <select
                  value={values[p.name] || ''}
                  onChange={e => setValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                >
                  <option value="">Select contract...</option>
                  {Object.entries(config.addresses).map(([key, addr]) => (
                    <option key={key} value={addr}>{config.manifest.contracts[key]?.label || key} ({addr.slice(0, 10)}...)</option>
                  ))}
                </select>
              </label>
            </div>
          );
        }

        const resolved = resolveParamValue(p, config, reads);
        const isAutoFilled = !!resolved;

        return (
          <div className="form-row" key={p.name}>
            <label>
              {p.label || p.name}
              {p.scale && <span style={{ fontSize: 11, color: 'var(--white-dim)', marginLeft: 6 }}>x{p.scale}</span>}
              <input
                value={values[p.name] || ''}
                onChange={e => setValues(prev => ({ ...prev, [p.name]: e.target.value }))}
                placeholder={p.placeholder}
                disabled={disabled || isAutoFilled}
                style={isAutoFilled ? { opacity: 0.6 } : {}}
              />
            </label>
          </div>
        );
      })}

      {error && <div className="warning" style={{ marginBottom: 8 }}>{error}</div>}

      {confirming && operation.confirm && (
        <div className="warning" style={{ marginBottom: 8 }}>{operation.confirm}</div>
      )}

      <div style={{ display: 'flex', gap: 8 }}>
        <button
          className="btn btn-primary"
          style={{ flex: 1 }}
          onClick={handleExecute}
          disabled={disabled || loading || !contractAddress}
        >
          {loading ? <span className="spinner" /> : confirming ? 'Confirm' : operation.label}
        </button>
        {confirming && (
          <button className="btn btn-secondary" onClick={() => setConfirming(false)}>Cancel</button>
        )}
      </div>
    </div>
  );
}
