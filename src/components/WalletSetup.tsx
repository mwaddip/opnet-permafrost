import { useState, useEffect, useRef, useCallback } from 'react';
import { generateWallet, skipWallet, getWalletBalance } from '../lib/api';
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
      setP2tr(result.config.permafrost?.frostP2tr || (result.config.wallet?.p2tr ?? null));
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
            <label htmlFor="dontShow" style={{ fontSize: 13, color: 'var(--white-dim)', cursor: 'pointer' }} title="Hide this setup step on future logins. Wallet can still be configured in Settings.">
              Don't show this again
            </label>
          </div>

          <button className="btn btn-secondary btn-full" onClick={handleSkip} disabled={loading} title="You can configure a wallet later in Settings. Without a wallet, signatures are display-only and cannot be broadcast.">
            Skip for now
          </button>
        </div>
      ) : (
        <div className="card">
          <h2>Backup Your Mnemonic</h2>
          <div className="warning">
            Write down these words and store them securely. This is the ONLY time they will be shown.
          </div>
          <div className="pubkey-display" style={{ fontSize: 15, lineHeight: 1.8, wordBreak: 'normal' }}>
            {mnemonic}
          </div>
          {p2tr && (
            <>
              <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }} title="Pay-to-Taproot Bitcoin address used to fund OPNet transaction fees">P2TR Address</h3>
              <div className="pubkey-display">{p2tr}</div>
              <WalletFunder p2tr={p2tr} />
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

// ── Wallet funder — balance polling + OPWallet top-up ──

function WalletFunder({ p2tr }: { p2tr: string }) {
  const [balance, setBalance] = useState('0');
  const [balanceSats, setBalanceSats] = useState(0);
  const [topUpAmount, setTopUpAmount] = useState('100000');
  const [txStatus, setTxStatus] = useState<'idle' | 'confirming' | 'sending' | 'confirmed' | 'error'>('idle');
  const [txMessage, setTxMessage] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const hasOpWallet = typeof window !== 'undefined' && !!(window as unknown as { opnet?: unknown }).opnet;

  const fetchBalance = useCallback(async () => {
    try {
      const result = await getWalletBalance();
      const sats = parseInt(result.balance) || 0;
      setBalanceSats(sats);
      setBalance((sats / 1e8).toFixed(8));
      return sats;
    } catch {
      return 0;
    }
  }, []);

  // Poll balance every 10s
  useEffect(() => {
    fetchBalance();
    pollRef.current = setInterval(fetchBalance, 10000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [fetchBalance]);

  // When balance arrives after a pending tx, mark confirmed
  useEffect(() => {
    if (txStatus === 'confirming' && balanceSats > 0) {
      setTxStatus('confirmed');
      setTxMessage('Funded!');
    }
  }, [balanceSats, txStatus]);

  const handleTopUp = async () => {
    const wallet = (window as unknown as {
      opnet?: {
        requestAccounts(): Promise<string[]>;
        web3: {
          sendBitcoin(params: {
            from: string; to: string; amount: bigint;
            feeRate: number; priorityFee: bigint; utxos: never[];
          }): Promise<{ tx: string; estimatedFees: bigint }>;
        };
      };
    }).opnet;

    if (!wallet) { setTxMessage('OPWallet not detected'); setTxStatus('error'); return; }

    const sats = parseInt(topUpAmount);
    if (!sats || sats <= 0) { setTxMessage('Enter an amount'); setTxStatus('error'); return; }

    setTxStatus('sending');
    setTxMessage('Confirm in OPWallet...');

    try {
      const accounts = await wallet.requestAccounts();
      if (!accounts.length) throw new Error('No accounts');

      const result = await wallet.web3.sendBitcoin({
        from: accounts[0]!,
        to: p2tr,
        amount: BigInt(sats),
        feeRate: 0,
        priorityFee: 0n,
        utxos: [],
      });

      setTxStatus('confirming');
      setTxMessage(`Sent — txid: ${result.tx.slice(0, 12)}...${result.tx.slice(-6)}`);
    } catch (e: unknown) {
      const err = e as { code?: number; message?: string };
      if (err.code === 4001) {
        setTxStatus('idle');
        setTxMessage('');
      } else {
        setTxStatus('error');
        setTxMessage(err.message || 'Transaction failed');
      }
    }
  };

  return (
    <div style={{ marginTop: 12, marginBottom: 16, padding: 12, background: 'var(--bg)', borderRadius: 'var(--radius)', border: '1px solid var(--border-dim)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <span style={{ fontSize: 13, color: 'var(--gray-light)' }}>Balance</span>
        <span style={{ fontSize: 16, fontWeight: 600, color: balanceSats > 0 ? 'var(--green)' : 'var(--white-dim)' }}>
          {balance} BTC
        </span>
      </div>

      {hasOpWallet && (
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <input
            type="number"
            value={topUpAmount}
            onChange={e => setTopUpAmount(e.target.value)}
            min={1000}
            step={1000}
            style={{ width: 100, fontSize: 13 }}
          />
          <span style={{ fontSize: 12, color: 'var(--white-dim)' }}>sats</span>
          <button
            className="btn btn-primary"
            style={{ fontSize: 13, padding: '6px 14px' }}
            onClick={handleTopUp}
            disabled={txStatus === 'sending' || txStatus === 'confirming'}
          >
            {txStatus === 'sending' ? <span className="spinner" /> : 'Fund via OPWallet'}
          </button>
        </div>
      )}

      {!hasOpWallet && (
        <p style={{ fontSize: 12, color: 'var(--white-dim)', margin: 0 }}>
          Send BTC to the address above to fund transactions.
        </p>
      )}

      {txMessage && (
        <div style={{
          marginTop: 8, fontSize: 12, fontFamily: 'monospace',
          color: txStatus === 'confirmed' ? 'var(--green)' : txStatus === 'error' ? 'var(--red)' : 'var(--accent)',
        }}>
          {txStatus === 'confirming' && <span className="spinner" style={{ width: 12, height: 12, borderWidth: 2, marginRight: 6, verticalAlign: 'middle' }} />}
          {txMessage}
        </div>
      )}
    </div>
  );
}
