import { useState, useEffect } from 'react';
import { encodeTx, readContract } from '../lib/api';
import type { ManifestOperation, ManifestConfig, ManifestParam } from '../lib/manifest-types';
import { resolveParamValue, encodeParamValue, resolveAbi } from '../lib/manifest';
import { fromHex } from '../lib/hex';

interface Props {
  operation: ManifestOperation;
  config: ManifestConfig;
  reads: Record<string, unknown>;
  onExecute: (contractAddress: string, method: string, params: string[], paramTypes: Array<'address' | 'u256' | 'bytes'>, messageHash: string, message: Uint8Array, abi?: unknown[]) => void;
  disabled?: boolean;
}

/** Hook to fetch indexed options for a param (e.g., list of pool addresses) */
function useParamOptions(param: ManifestParam, config: ManifestConfig) {
  const [options, setOptions] = useState<string[] | null>(null);

  useEffect(() => {
    if (!param.options) return;
    const { count, item } = param.options;
    const countAddr = config.addresses[count.contract];
    const itemAddr = config.addresses[item.contract];
    if (!countAddr || !itemAddr) return;

    const countAbi = config.manifest.contracts[count.contract]?.abi;
    const itemAbi = config.manifest.contracts[item.contract]?.abi;
    const countAbiArr = countAbi ? (Array.isArray(countAbi) ? countAbi : [countAbi]) : undefined;
    const itemAbiArr = itemAbi ? (Array.isArray(itemAbi) ? itemAbi : [itemAbi]) : undefined;

    let cancelled = false;
    (async () => {
      try {
        const countResult = await readContract(countAddr, count.method, countAbiArr);
        const firstKey = Object.keys(countResult.result)[0];
        const n = Number(firstKey ? countResult.result[firstKey] : 0);
        if (cancelled || n <= 0) { setOptions([]); return; }

        const items: string[] = [];
        for (let i = 0; i < n; i++) {
          const itemResult = await readContract(itemAddr, item.method, itemAbiArr, [i.toString()]);
          const itemKey = Object.keys(itemResult.result)[0];
          if (itemKey) items.push(String(itemResult.result[itemKey]));
        }
        if (!cancelled) setOptions(items);
      } catch {
        if (!cancelled) setOptions([]);
      }
    })();
    return () => { cancelled = true; };
  }, [param.options, config]);

  return options;
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
        if (!raw && !p.source && !p.options) { setError(`${p.label || p.name} is required`); setLoading(false); return; }
        const encoded = encodeParamValue(raw, p);
        params.push(encoded);
        const mappedType = p.type === 'uint256' ? 'u256' : p.type === 'bool' ? 'u256' : p.type as 'address' | 'bytes';
        if (p.type === 'bool') params[params.length - 1] = raw === 'true' || raw === '1' ? '1' : '0';
        paramTypes.push(mappedType);
      }

      const result = await encodeTx(operation.method, params, paramTypes);
      const msgBytes = fromHex(result.calldata);
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

        return <ParamInput key={p.name} param={p} config={config} value={values[p.name] || ''} disabled={disabled || isAutoFilled} dimmed={isAutoFilled} onChange={v => setValues(prev => ({ ...prev, [p.name]: v }))} />;
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

/** Individual param input — renders as dropdown when options are configured */
function ParamInput({ param, config, value, disabled, dimmed, onChange }: {
  param: ManifestParam;
  config: ManifestConfig;
  value: string;
  disabled?: boolean;
  dimmed?: boolean;
  onChange: (v: string) => void;
}) {
  const options = useParamOptions(param, config);

  return (
    <div className="form-row">
      <label>
        {param.label || param.name}
        {param.scale && <span style={{ fontSize: 11, color: 'var(--white-dim)', marginLeft: 6 }} title="Your input is multiplied by this value before sending. For 8-decimal tokens, enter human-readable amounts (e.g. 100 instead of 10000000000).">x{param.scale}</span>}
        {options !== null ? (
          <select
            value={value}
            onChange={e => onChange(e.target.value)}
            disabled={disabled}
            style={dimmed ? { opacity: 0.6 } : {}}
          >
            <option value="">Select...</option>
            {options.map((opt, i) => (
              <option key={i} value={opt}>
                {opt.length > 20 ? `${opt.slice(0, 10)}...${opt.slice(-8)}` : opt}
              </option>
            ))}
          </select>
        ) : (
          <input
            value={value}
            onChange={e => onChange(e.target.value)}
            placeholder={param.placeholder}
            disabled={disabled}
            style={dimmed ? { opacity: 0.6 } : {}}
          />
        )}
      </label>
    </div>
  );
}
