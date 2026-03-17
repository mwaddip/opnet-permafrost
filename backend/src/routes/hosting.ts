import { Router, type Request, type Response, type RequestHandler } from 'express';
import { writeFileSync, existsSync } from 'node:fs';
import { execSync, spawn } from 'node:child_process';
import { ConfigStore } from '../lib/config-store.js';
import { sanitizeConfig, type HostingConfig } from '../lib/types.js';


const CADDYFILE = process.env.CADDYFILE_PATH || '/etc/caddy/Caddyfile';
const BACKEND_PORT = parseInt(process.env.PORT || '8080', 10);

function writeCaddyfile(hosting: HostingConfig) {
  const upstream = `localhost:${BACKEND_PORT}`;

  let config: string;
  if (hosting.httpsEnabled && hosting.domain) {
    // HTTPS with automatic Let's Encrypt
    config = `${hosting.domain} {
  reverse_proxy ${upstream}
}
`;
  } else if (hosting.domain) {
    // HTTP only on port 80
    config = `http://${hosting.domain} {
  reverse_proxy ${upstream}
}
`;
  } else {
    // Default: listen on :80, proxy to backend
    config = `:80 {
  reverse_proxy ${upstream}
}
`;
  }

  writeFileSync(CADDYFILE, config, 'utf-8');
}

function reloadCaddy(): string | null {
  try {
    // Check if caddy is available
    execSync('which caddy', { stdio: 'ignore' });
  } catch {
    return 'Caddy is not installed. Hosting changes saved but will take effect on next Docker restart.';
  }

  try {
    // Try reload first (if caddy is already running)
    execSync('caddy reload --config /etc/caddy/Caddyfile --force 2>&1', {
      timeout: 10000,
    });
    return null;
  } catch {
    // Caddy not running yet — start it
    try {
      spawn('caddy', ['run', '--config', '/etc/caddy/Caddyfile'], {
        stdio: 'ignore',
        detached: true,
      }).unref();
      return null;
    } catch (e) {
      return `Failed to start Caddy: ${(e as Error).message}`;
    }
  }
}

export function hostingRoutes(store: ConfigStore, requireAdmin: RequestHandler): Router {
  const r = Router();

  /** GET /api/hosting — current hosting config */
  r.get('/', (_req: Request, res: Response) => {
    try {
      const config = store.get();
      res.json({ hosting: config.hosting || null });
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  /** POST /api/hosting — update domain + HTTPS settings */
  r.post('/', requireAdmin, (req: Request, res: Response) => {
    const { domain, httpsEnabled } = req.body as {
      domain?: string;
      httpsEnabled?: boolean;
    };

    try {
      const hosting: HostingConfig = {
        domain: (domain || '').trim(),
        httpsEnabled: !!httpsEnabled,
        httpsStatus: httpsEnabled ? 'pending' : undefined,
      };

      // Save to config
      store.update({ hosting });

      // Write Caddyfile and reload
      writeCaddyfile(hosting);
      const err = reloadCaddy();

      if (err) {
        hosting.httpsStatus = httpsEnabled ? 'error' : undefined;
        hosting.httpsError = err;
        store.update({ hosting });
        res.json({ ok: true, warning: err, config: sanitizeConfig(store.get()) });
      } else {
        if (httpsEnabled) {
          hosting.httpsStatus = 'active';
          store.update({ hosting });
        }
        res.json({ ok: true, config: sanitizeConfig(store.get()) });
      }
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  /** DELETE /api/hosting — remove domain config, revert to default */
  r.delete('/', requireAdmin, (_req: Request, res: Response) => {
    try {
      store.update({ hosting: undefined as never });

      // Write default Caddyfile
      writeCaddyfile({ domain: '', httpsEnabled: false });
      reloadCaddy();

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  return r;
}
