import { useState } from 'react';
import { downloadBackup } from '../lib/api';

interface Props {
  onDownloaded: () => void;
}

/**
 * Persistent top-of-page banner for portable mode admins after DKG completes.
 * Reminds the admin to download their encrypted config before the server
 * restarts and wipes everything from memory. Reuses the existing backup flow.
 */
export function PortableConfigBanner({ onDownloaded }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleDownload = async () => {
    if (!password) { setError('Password required'); return; }
    setLoading(true);
    setError('');
    try {
      const result = await downloadBackup(password);
      const blob = new Blob([result.encrypted], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `otzi-portable-config-${new Date().toISOString().slice(0, 10)}.enc`;
      a.click();
      URL.revokeObjectURL(url);
      setPassword('');
      onDownloaded();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        background: 'var(--accent)',
        color: '#000',
        padding: '16px 24px',
        borderBottom: '2px solid var(--accent-hover, var(--accent))',
        boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
        position: 'sticky',
        top: 0,
        zIndex: 1000,
      }}
    >
      <div style={{ maxWidth: 900, margin: '0 auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: '1 1 300px' }}>
            <div style={{ fontWeight: 700, fontSize: 18, marginBottom: 4 }}>
              Download your encrypted config
            </div>
            <div style={{ fontSize: 13, opacity: 0.85 }}>
              Portable mode keeps everything in memory. If the server restarts before you download, all keys are lost.
            </div>
          </div>
          {!expanded && (
            <button
              onClick={() => setExpanded(true)}
              style={{
                background: '#000',
                color: 'var(--accent)',
                border: 'none',
                padding: '12px 24px',
                fontSize: 16,
                fontWeight: 700,
                fontFamily: 'inherit',
                cursor: 'pointer',
                borderRadius: 'var(--radius)',
                whiteSpace: 'nowrap',
              }}
            >
              Download Encrypted Config
            </button>
          )}
        </div>

        {expanded && (
          <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Encryption password"
              autoFocus
              onKeyDown={(e) => e.key === 'Enter' && handleDownload()}
              style={{
                flex: '1 1 200px',
                padding: '10px 12px',
                fontSize: 14,
                fontFamily: 'inherit',
                border: '1px solid #000',
                borderRadius: 'var(--radius)',
                background: '#fff',
                color: '#000',
              }}
            />
            <button
              onClick={handleDownload}
              disabled={loading || !password}
              style={{
                background: '#000',
                color: 'var(--accent)',
                border: 'none',
                padding: '10px 20px',
                fontSize: 14,
                fontWeight: 700,
                fontFamily: 'inherit',
                cursor: loading || !password ? 'not-allowed' : 'pointer',
                borderRadius: 'var(--radius)',
                opacity: loading || !password ? 0.6 : 1,
              }}
            >
              {loading ? 'Downloading...' : 'Download'}
            </button>
            <button
              onClick={() => { setExpanded(false); setPassword(''); setError(''); }}
              disabled={loading}
              style={{
                background: 'transparent',
                color: '#000',
                border: '1px solid #000',
                padding: '10px 16px',
                fontSize: 14,
                fontFamily: 'inherit',
                cursor: 'pointer',
                borderRadius: 'var(--radius)',
              }}
            >
              Cancel
            </button>
          </div>
        )}

        {error && (
          <div style={{ marginTop: 8, fontSize: 13, fontWeight: 600 }}>
            Error: {error}
          </div>
        )}
      </div>
    </div>
  );
}
