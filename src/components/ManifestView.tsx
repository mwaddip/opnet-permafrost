import type { ManifestConfig } from '../lib/manifest-types';
import { useManifestState } from '../lib/manifest-state';
import { evaluateCondition, formatReadValue } from '../lib/manifest';
import { OperationCard } from './OperationCard';

interface Props {
  config: ManifestConfig;
  onExecute: (contractAddress: string, method: string, params: string[], paramTypes: Array<'address' | 'u256' | 'bytes'>, messageHash: string, message: Uint8Array, abi?: unknown[]) => void;
  disabled?: boolean;
  isAdmin?: boolean;
}

export function ManifestView({ config, onExecute, disabled, isAdmin }: Props) {
  const { reads, currentBlock, loading } = useManifestState(config);

  const manifest = config.manifest;
  const visibleOps = manifest.operations.filter(op => {
    if (op.ownerOnly && !isAdmin) return false;
    if (!op.condition) return true;
    return evaluateCondition(op.condition, reads, currentBlock);
  });

  return (
    <div>
      {/* Project header */}
      <div style={{ marginBottom: 16 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          {manifest.icon && <img src={manifest.icon} alt="" style={{ width: 24, height: 24, borderRadius: 4 }} onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />}
          <h2 style={{ margin: 0, fontSize: 16 }}>{manifest.name}</h2>
          {loading && <span className="spinner" style={{ width: 14, height: 14, borderWidth: 2 }} />}
        </div>
        {manifest.description && (
          <p style={{ fontSize: 12, color: 'var(--white-dim)', margin: 0 }}>{manifest.description}</p>
        )}
      </div>

      {/* Status panel */}
      {manifest.status && manifest.status.length > 0 && (
        <div className="card" style={{ marginBottom: 16 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 12 }}>
            {manifest.status.map(entry => {
              const readDef = manifest.reads?.[entry.read];
              const value = reads[entry.read];
              const conditionMet = !entry.condition || evaluateCondition(entry.condition, reads, currentBlock);
              const display = !conditionMet ? 'N/A'
                : value !== undefined ? formatReadValue(value, readDef?.format, entry.map)
                : '—';
              return (
                <div key={entry.read}>
                  <div style={{ fontSize: 11, color: 'var(--gray-light)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    {entry.label}
                  </div>
                  <div style={{ fontSize: 15, fontWeight: 600, fontFamily: 'monospace', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: !conditionMet ? 'var(--gray)' : undefined }} title={display}>
                    {display}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Operations */}
      {visibleOps.length === 0 && (
        <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>No operations available in the current state.</p>
      )}
      {visibleOps.map(op => (
        <OperationCard
          key={op.id}
          operation={op}
          config={config}
          reads={reads}
          onExecute={onExecute}
          disabled={disabled}
        />
      ))}
    </div>
  );
}
