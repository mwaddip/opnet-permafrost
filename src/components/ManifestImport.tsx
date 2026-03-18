import { useState, useEffect } from 'react';
import { getManifest, saveManifest } from '../lib/api';
import { validateManifest } from '../lib/manifest';
import type { ManifestConfig } from '../lib/manifest-types';

interface Props {
  disabled?: boolean;
}

export function ManifestImport({ disabled }: Props) {
  const [config, setConfig] = useState<ManifestConfig | null>(null);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [addresses, setAddresses] = useState<Record<string, string>>({});
  const [settings, setSettings] = useState<Record<string, string>>({});

  useEffect(() => {
    getManifest().then(r => {
      if (r.manifestConfig) {
        const mc = r.manifestConfig as ManifestConfig;
        setConfig(mc);
        setAddresses(mc.addresses || {});
        setSettings(mc.settings || {});
      }
    }).catch(() => {});
  }, []);

  const handleImport = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json,.otzi.json';
    input.onchange = async (e) => {
      const file = (e.target as HTMLInputElement).files?.[0];
      if (!file) return;
      try {
        const text = await file.text();
        const parsed = JSON.parse(text);
        const result = validateManifest(parsed);
        if (!result.valid) { setError(result.error); return; }

        const newAddresses: Record<string, string> = {};
        for (const key of Object.keys(result.manifest.contracts)) {
          newAddresses[key] = addresses[key] || '';
        }

        const newSettings: Record<string, string> = {};
        for (const op of result.manifest.operations) {
          for (const p of op.params) {
            if (p.source?.startsWith('setting:')) {
              const settingKey = p.source.split(':')[1]!;
              newSettings[settingKey] = settings[settingKey] || '';
            }
          }
        }

        const mc: ManifestConfig = { manifest: result.manifest, addresses: newAddresses, settings: newSettings };
        setConfig(mc);
        setAddresses(newAddresses);
        setSettings(newSettings);
        setError('');
        setMessage(`Loaded "${result.manifest.name}" — configure contract addresses below.`);
      } catch (e) {
        setError((e as Error).message);
      }
    };
    input.click();
  };

  const handleSave = async () => {
    if (!config) return;
    setSaving(true);
    setError('');
    try {
      const mc: ManifestConfig = { ...config, addresses, settings };
      await saveManifest(mc);
      setConfig(mc);
      setMessage('Manifest saved.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async () => {
    setSaving(true);
    try {
      await saveManifest(null);
      setConfig(null);
      setAddresses({});
      setSettings({});
      setMessage('Manifest removed.');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  const hasAllAddresses = config ? Object.values(addresses).every(a => a.trim()) : false;

  return (
    <div className="card" style={disabled ? { opacity: 0.5, pointerEvents: 'none' } : {}}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ marginBottom: 0 }}>Project Manifest</h2>
        <button className="btn btn-secondary" style={{ fontSize: 13, padding: '6px 14px' }} onClick={handleImport}>
          {config ? 'Replace' : 'Import .otzi.json'}
        </button>
      </div>

      {!config && (
        <p style={{ fontSize: 13, color: 'var(--white-dim)' }}>
          Import a project manifest to configure custom contract operations, status panels, and theming.
        </p>
      )}

      {config && (
        <>
          <div style={{ marginBottom: 12, padding: 10, background: 'var(--bg)', borderRadius: 'var(--radius)', border: '1px solid var(--border-dim)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {config.manifest.icon && <img src={config.manifest.icon} alt="" style={{ width: 20, height: 20, borderRadius: 4 }} />}
              <strong style={{ fontSize: 14 }}>{config.manifest.name}</strong>
            </div>
            {config.manifest.description && (
              <div style={{ fontSize: 12, color: 'var(--white-dim)', marginTop: 4 }}>{config.manifest.description}</div>
            )}
            <div style={{ fontSize: 11, color: 'var(--gray-light)', marginTop: 4 }}>
              {Object.keys(config.manifest.contracts).length} contracts · {config.manifest.operations.length} operations
              {config.manifest.reads ? ` · ${Object.keys(config.manifest.reads).length} reads` : ''}
            </div>
          </div>

          <h3 style={{ fontSize: 14, marginBottom: 8 }}>Contract Addresses</h3>
          {Object.entries(config.manifest.contracts).map(([key, contract]) => (
            <div className="form-row" key={key}>
              <label>
                {contract.label} <span style={{ fontSize: 11, color: 'var(--gray-light)' }}>({key})</span>
                <input
                  value={addresses[key] || ''}
                  onChange={e => setAddresses(prev => ({ ...prev, [key]: e.target.value }))}
                  placeholder="0x..."
                  style={{ fontFamily: 'monospace', fontSize: 12 }}
                />
              </label>
            </div>
          ))}

          {Object.keys(settings).length > 0 && (
            <>
              <h3 style={{ fontSize: 14, marginBottom: 8, marginTop: 16 }}>Settings</h3>
              {Object.keys(settings).map(key => (
                <div className="form-row" key={key}>
                  <label>
                    {key}
                    <input
                      value={settings[key] || ''}
                      onChange={e => setSettings(prev => ({ ...prev, [key]: e.target.value }))}
                      placeholder="0x..."
                      style={{ fontFamily: 'monospace', fontSize: 12 }}
                    />
                  </label>
                </div>
              ))}
            </>
          )}

          {error && <div className="warning" style={{ marginBottom: 8 }}>{error}</div>}
          {message && <div style={{ fontSize: 13, color: 'var(--accent)', marginBottom: 8 }}>{message}</div>}

          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn btn-primary" style={{ flex: 1 }} onClick={handleSave}
              disabled={saving || !hasAllAddresses}>
              {saving ? <span className="spinner" /> : 'Save'}
            </button>
            <button className="btn btn-secondary" style={{ color: 'var(--red)' }} onClick={handleRemove} disabled={saving}>
              Remove
            </button>
          </div>
        </>
      )}
    </div>
  );
}
