import { useState, useCallback, useEffect, useRef } from 'react';
import { OP20_METHODS, type MethodDef } from '../lib/op20-methods';
import { encodeTx } from '../lib/api';
import type { ContractConfig } from '../lib/vault-types';
import type { SendPrefill } from '../App';

type InputMode = 'configured' | 'op20' | 'abi' | 'raw';

interface Props {
  contracts: ContractConfig[];
  onMessageBuilt: (message: Uint8Array, meta: MessageMeta) => void;
  prefill?: SendPrefill | null;
  onPrefillConsumed?: () => void;
}

export interface MessageMeta {
  contractAddress: string;
  method: string;
  params: Record<string, string>;
  paramTypes: Array<'address' | 'u256' | 'bytes'>;
  messageHash: string;
}

export function MessageBuilder({ contracts, onMessageBuilt, prefill, onPrefillConsumed }: Props) {
  const hasConfiguredContracts = contracts.length > 0;
  const firstParamRef = useRef<HTMLInputElement>(null);

  const [mode, setMode] = useState<InputMode>(hasConfiguredContracts ? 'configured' : 'op20');
  const [contractAddr, setContractAddr] = useState(hasConfiguredContracts ? contracts[0]!.address : '');
  const [selectedMethod, setSelectedMethod] = useState('');
  const [paramValues, setParamValues] = useState<Record<string, string>>({});
  const [rawHex, setRawHex] = useState('');
  const [abiText, setAbiText] = useState('');
  const [abiMethods, setAbiMethods] = useState<MethodDef[]>([]);
  const [error, setError] = useState('');

  // Handle prefill from Settings "send" link
  useEffect(() => {
    if (!prefill) return;
    const isConfigured = contracts.some(c => c.address === prefill.contractAddress);
    if (isConfigured) {
      setMode('configured');
      setContractAddr(prefill.contractAddress);
      setSelectedMethod(prefill.method);
      setParamValues({});
      // Focus first param input after render
      setTimeout(() => firstParamRef.current?.focus(), 50);
    }
    onPrefillConsumed?.();
  }, [prefill, contracts, onPrefillConsumed]);

  // Determine available methods based on mode
  const getAvailableMethods = (): MethodDef[] => {
    if (mode === 'configured') {
      const contract = contracts.find(c => c.address === contractAddr);
      if (!contract) return [];
      if (contract.abi && contract.abi.length > 0) {
        return parseAbiMethods(contract.abi).filter(m => contract.methods.includes(m.name));
      }
      return OP20_METHODS.filter(m => contract.methods.includes(m.name));
    }
    if (mode === 'abi') return abiMethods;
    if (mode === 'op20') return OP20_METHODS;
    return [];
  };

  const methods = getAvailableMethods();
  const currentMethod = methods.find(m => m.name === selectedMethod);

  const handleParamChange = (name: string, value: string) => {
    setParamValues(prev => ({ ...prev, [name]: value }));
  };

  const handleParseAbi = () => {
    try {
      const abi = JSON.parse(abiText);
      const parsed = parseAbiMethods(abi);
      setAbiMethods(parsed);
      setError('');
    } catch {
      setError('Invalid ABI JSON');
    }
  };

  const handleBuild = useCallback(async () => {
    setError('');
    try {
      let message: Uint8Array;

      let messageHash: string;

      if (mode === 'raw') {
        const hex = rawHex.replace(/^0x/, '');
        message = new Uint8Array(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        const hashBuf = await crypto.subtle.digest('SHA-256', new Uint8Array(message).buffer as ArrayBuffer);
        messageHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
      } else {
        if (!contractAddr || !selectedMethod) {
          setError('Select a contract and method');
          return;
        }
        // Use backend to encode calldata with BinaryWriter (proper OPNet encoding)
        const paramNames = currentMethod?.params.map(p => p.name) || [];
        const paramVals = paramNames.map(n => paramValues[n] || '');
        const paramTypes = (currentMethod?.params || []).map(p => p.type);

        const encoded = await encodeTx(selectedMethod, paramVals, paramTypes);
        const hex = encoded.calldata;
        message = new Uint8Array(hex.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        messageHash = encoded.messageHash;
      }

      onMessageBuilt(message, {
        contractAddress: contractAddr,
        method: selectedMethod || 'raw',
        params: paramValues,
        paramTypes: (currentMethod?.params || []).map(p => p.type),
        messageHash,
      });
    } catch (e) {
      setError((e as Error).message);
    }
  }, [mode, contractAddr, selectedMethod, paramValues, rawHex, currentMethod, onMessageBuilt]);

  const tabs: { key: InputMode; label: string; disabled?: boolean }[] = [
    ...(hasConfiguredContracts ? [{ key: 'configured' as const, label: 'Configured' }] : [{ key: 'configured' as const, label: 'Configured', disabled: true }]),
    { key: 'op20', label: 'OP-20' },
    { key: 'abi', label: 'Custom ABI' },
    { key: 'raw', label: 'Raw Hex' },
  ];

  return (
    <div className="card">
      <h2>Build Message</h2>

      {/* Mode tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        {tabs.map(t => (
          <button
            key={t.key}
            className={`btn ${mode === t.key ? 'btn-primary' : 'btn-secondary'}`}
            style={{ flex: 1, padding: '8px 12px', fontSize: 13, opacity: t.disabled ? 0.4 : 1 }}
            onClick={() => { if (!t.disabled) { setMode(t.key); setSelectedMethod(''); setContractAddr(t.key === 'configured' && hasConfiguredContracts ? contracts[0]!.address : ''); setError(''); } }}
            disabled={t.disabled}
            title={t.disabled ? 'No contracts configured — add them in Settings' : undefined}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Configured mode: contract dropdown */}
      {mode === 'configured' && (
        <div className="form-row">
          <label>
            Contract
            <select value={contractAddr} onChange={e => { setContractAddr(e.target.value); setSelectedMethod(''); }}>
              {contracts.map(c => (
                <option key={c.address} value={c.address}>{c.name || c.address}</option>
              ))}
            </select>
          </label>
        </div>
      )}

      {/* OP-20 / ABI mode: manual address input */}
      {(mode === 'op20' || mode === 'abi') && (
        <div className="form-row">
          <label>
            Contract Address
            <input
              value={contractAddr}
              onChange={e => setContractAddr(e.target.value)}
              placeholder="0x..."
            />
          </label>
        </div>
      )}

      {/* ABI paste area */}
      {mode === 'abi' && (
        <div style={{ marginBottom: 16 }}>
          <textarea
            className="blob-textarea"
            value={abiText}
            onChange={e => setAbiText(e.target.value)}
            placeholder="Paste ABI JSON here..."
            rows={4}
          />
          <button className="btn btn-secondary" style={{ marginTop: 8 }} onClick={handleParseAbi}>
            Parse ABI
          </button>
        </div>
      )}

      {/* Method selector */}
      {mode !== 'raw' && methods.length > 0 && (
        <div className="form-row">
          <label>
            Method
            <select value={selectedMethod} onChange={e => { setSelectedMethod(e.target.value); setParamValues({}); setTimeout(() => firstParamRef.current?.focus(), 50); }}>
              <option value="">Select method...</option>
              {methods.map(m => (
                <option key={m.name} value={m.name}>{m.label || m.name}</option>
              ))}
            </select>
          </label>
        </div>
      )}

      {/* Dynamic params */}
      {currentMethod && currentMethod.params.map((p, i) => (
        <div className="form-row" key={p.name}>
          <label>
            {p.name} <span style={{ color: 'var(--gray)', fontWeight: 400 }}>({p.type})</span>
            <input
              ref={i === 0 ? firstParamRef : undefined}
              value={paramValues[p.name] || ''}
              onChange={e => handleParamChange(p.name, e.target.value)}
              placeholder={p.placeholder || p.name}
            />
          </label>
        </div>
      ))}

      {/* Raw hex input */}
      {mode === 'raw' && (
        <div className="form-row">
          <label>
            Message (hex)
            <textarea
              className="blob-textarea"
              value={rawHex}
              onChange={e => setRawHex(e.target.value)}
              placeholder="0x..."
              rows={3}
            />
          </label>
        </div>
      )}

      {error && <div className="warning">{error}</div>}

      <button className="btn btn-primary btn-full" onClick={handleBuild}>
        Build Message
      </button>
    </div>
  );
}

// ── Helpers ──

function parseAbiMethods(abi: unknown[]): MethodDef[] {
  return (abi as Array<{ name?: string; inputs?: Array<{ name: string; type: string }> }>)
    .filter(entry => entry.name && entry.inputs)
    .map(entry => ({
      name: entry.name!,
      label: entry.name!,
      params: (entry.inputs || []).map(inp => ({
        name: inp.name,
        type: mapAbiType(inp.type),
        placeholder: `${inp.name} (${inp.type})`,
      })),
    }));
}

function mapAbiType(abiType: string): 'address' | 'u256' | 'bytes' {
  if (abiType.includes('address') || abiType.includes('Address')) return 'address';
  if (abiType.includes('uint') || abiType.includes('int') || abiType.includes('u256')) return 'u256';
  return 'bytes';
}
