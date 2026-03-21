import { Router, type Request, type Response, type RequestHandler } from 'express';
import { writeFileSync } from 'node:fs';
import { execSync, spawn } from 'node:child_process';
import { ConfigStore } from '../lib/config-store.js';
import { sanitizeConfig, type HostingConfig } from '../lib/types.js';

const CADDYFILE = process.env.CADDYFILE_PATH || '/etc/caddy/Caddyfile';
const BACKEND_PORT = parseInt(process.env.PORT || '8080', 10);

// Detect Caddy availability once at startup
let hasCaddy = false;
try {
  execSync('which caddy', { stdio: 'ignore' });
  hasCaddy = true;
} catch { /* not installed */ }

function writeCaddyfile(hosting: HostingConfig) {
  const upstream = `localhost:${BACKEND_PORT}`;
  const pathPrefix = hosting.path ? hosting.path.replace(/\/+$/, '') : '';

  let config: string;
  if (hosting.httpsEnabled && hosting.domain) {
    const listen = hosting.port ? `${hosting.domain}:${hosting.port}` : hosting.domain;
    config = `${listen} {\n`;
    if (pathPrefix) {
      config += `  handle_path ${pathPrefix}/* {\n    reverse_proxy ${upstream}\n  }\n`;
    } else {
      config += `  reverse_proxy ${upstream}\n`;
    }
    config += '}\n';
  } else if (hosting.domain) {
    const port = hosting.port || 80;
    config = `http://${hosting.domain}:${port} {\n`;
    if (pathPrefix) {
      config += `  handle_path ${pathPrefix}/* {\n    reverse_proxy ${upstream}\n  }\n`;
    } else {
      config += `  reverse_proxy ${upstream}\n`;
    }
    config += '}\n';
  } else {
    const port = hosting.port || 80;
    config = `:${port} {\n  reverse_proxy ${upstream}\n}\n`;
  }

  writeFileSync(CADDYFILE, config, 'utf-8');
}

function reloadCaddy(): string | null {
  if (!hasCaddy) {
    return 'Caddy is not installed. Hosting changes saved but will take effect on next Docker restart.';
  }

  try {
    execSync('caddy reload --config /etc/caddy/Caddyfile --force 2>&1', { timeout: 10000 });
    return null;
  } catch {
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

export function hostingRoutes(store: ConfigStore, requireAdmin: RequestHandler, requireRead: RequestHandler): Router {
  const r = Router();

  /** GET /api/hosting — current hosting config + caddy availability */
  r.get('/', requireRead, (_req: Request, res: Response) => {
    try {
      const config = store.get();
      res.json({ hosting: config.hosting || null, hasCaddy });
    } catch (e) {
      res.status(503).json({ error: (e as Error).message });
    }
  });

  /** POST /api/hosting — update domain, port, path, HTTPS settings */
  r.post('/', requireAdmin, (req: Request, res: Response) => {
    const { domain, port, path, httpsEnabled } = req.body as {
      domain?: string;
      port?: number;
      path?: string;
      httpsEnabled?: boolean;
    };

    // Sanitize domain — only allow valid hostname characters
    const cleanDomain = (domain || '').trim().replace(/[^a-zA-Z0-9.\-]/g, '');
    // Sanitize path — only allow URL path characters, must start with /
    let cleanPath = (path || '').trim().replace(/[^a-zA-Z0-9/\-_]/g, '');
    if (cleanPath && !cleanPath.startsWith('/')) cleanPath = '/' + cleanPath;
    // Sanitize port
    const cleanPort = port && port > 0 && port <= 65535 ? port : undefined;

    try {
      const hosting: HostingConfig = {
        domain: cleanDomain,
        port: cleanPort,
        path: cleanPath || undefined,
        httpsEnabled: !!httpsEnabled,
        httpsStatus: httpsEnabled ? 'pending' : undefined,
      };

      store.update({ hosting });

      if (hasCaddy) {
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
      } else {
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

      if (hasCaddy) {
        writeCaddyfile({ domain: '', httpsEnabled: false });
        reloadCaddy();
      }

      res.json({ ok: true });
    } catch (e) {
      res.status(500).json({ error: (e as Error).message });
    }
  });

  return r;
}
