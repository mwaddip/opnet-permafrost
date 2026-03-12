import { useState, useEffect, useCallback } from 'react';
import { InstallWizard } from './components/InstallWizard';
import { WalletSetup } from './components/WalletSetup';
import { DKGWizard } from './components/DKGWizard';
import { SigningPage } from './components/SigningPage';
import { Settings } from './components/Settings';
import { getStatus, type StatusResponse } from './lib/api';
import type { VaultConfig } from './lib/vault-types';
import './styles/global.css';
import './styles/ceremony.css';

type View = 'loading' | 'wizard' | 'unlock' | 'wallet' | 'dkg' | 'signing' | 'settings';

export function App() {
  const [view, setView] = useState<View>('loading');

  const checkStatus = useCallback(async () => {
    try {
      const status = await getStatus();
      if (status.state === 'fresh') {
        setView('wizard');
      } else if (status.state === 'locked') {
        setView('unlock');
      } else if (status.setupState) {
        if (!status.setupState.walletSkipped && !status.walletConfigured && !status.setupState.walletDontShowAgain) {
          setView('wallet');
        } else if (!status.setupState.dkgComplete) {
          setView('dkg');
        } else {
          setView('signing');
        }
      }
    } catch (e) {
      console.error('Failed to check status:', e);
      setView('wizard'); // fallback to wizard on error
    }
  }, []);

  useEffect(() => { checkStatus(); }, [checkStatus]);

  const handleSetupComplete = useCallback(() => { checkStatus(); }, [checkStatus]);

  if (view === 'loading') {
    return <div className="ceremony"><div className="spinner" /></div>;
  }

  if (view === 'wizard') {
    return <InstallWizard onComplete={handleSetupComplete} />;
  }

  if (view === 'unlock') {
    return <UnlockScreen onUnlocked={handleSetupComplete} />;
  }

  if (view === 'wallet') {
    return <WalletSetup onComplete={handleSetupComplete} />;
  }

  if (view === 'dkg') {
    return <DKGWizard onComplete={handleSetupComplete} />;
  }

  if (view === 'settings') {
    return <Settings onBack={() => setView('signing')} />;
  }

  return <SigningPage onSettings={() => setView('settings')} />;
}

/** Simple unlock screen for encrypted-persistent mode */
function UnlockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleUnlock = async () => {
    setLoading(true);
    setError('');
    try {
      const { unlock } = await import('./lib/api');
      await unlock(password);
      onUnlocked();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="ceremony">
      <h1>PERMAFROST Vault</h1>
      <p className="subtitle">Enter your password to unlock</p>
      <div className="card">
        <input
          type="password"
          value={password}
          onChange={e => setPassword(e.target.value)}
          placeholder="Password"
          onKeyDown={e => e.key === 'Enter' && handleUnlock()}
          style={{ width: '100%', marginBottom: 16 }}
        />
        {error && <div className="warning">{error}</div>}
        <button className="btn btn-primary btn-full" onClick={handleUnlock} disabled={loading || !password}>
          {loading ? <span className="spinner" /> : 'Unlock'}
        </button>
      </div>
    </div>
  );
}
