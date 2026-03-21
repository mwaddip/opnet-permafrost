import { useState, useEffect, useRef, useCallback } from 'react';
import { readContract, getBlockHeight } from './api';
import type { ManifestConfig, ManifestRead } from './manifest-types';

const POLL_INTERVAL = 30_000; // 30 seconds

export function useManifestState(config: ManifestConfig | null) {
  const [reads, setReads] = useState<Record<string, unknown>>({});
  const [currentBlock, setCurrentBlock] = useState<number | undefined>(undefined);
  const [loading, setLoading] = useState(false);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchAll = useCallback(async () => {
    if (!config?.manifest.reads) return;

    const readDefs = config.manifest.reads;
    const entries = Object.entries(readDefs);
    if (entries.length === 0) return;

    setLoading(true);
    const results: Record<string, unknown> = {};

    // Fetch block height in parallel with reads
    const blockPromise = getBlockHeight().then(r => setCurrentBlock(r.height)).catch(() => {});

    await Promise.all([
      blockPromise,
      ...entries.map(async ([key, def]: [string, ManifestRead]) => {
        const contractKey = def.contract;
        const address = config.addresses[contractKey];
        if (!address) return;

        // Send raw ABI (may contain "OP_20" shorthands) — backend resolves them
        // with proper output types from the opnet SDK
        const rawAbi = config.manifest.contracts[contractKey]?.abi;
        const abiArray = rawAbi ? (Array.isArray(rawAbi) ? rawAbi : [rawAbi]) : undefined;

        try {
          // Resolve parameterized reads (e.g., balanceOf with address from config)
          const callParams = def.params?.map(p => {
            const [sourceType, sourceKey] = p.source.split(':');
            if (sourceType === 'contract') return config.addresses[sourceKey!];
            if (sourceType === 'setting') return config.settings?.[sourceKey!];
            return undefined;
          }).filter(Boolean) as string[] | undefined;

          const response = await readContract(address, def.method, abiArray, callParams);
          const props = response.result;
          const firstKey = Object.keys(props)[0];
          results[key] = firstKey ? props[firstKey] : undefined;
        } catch {
          // Silently skip failed reads
        }
      }),
    ]);

    setReads(prev => ({ ...prev, ...results }));
    setLoading(false);
  }, [config]);

  useEffect(() => {
    if (!config?.manifest.reads) return;

    fetchAll();
    pollRef.current = setInterval(fetchAll, POLL_INTERVAL);

    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [config, fetchAll]);

  return { reads, currentBlock, loading, refresh: fetchAll };
}
