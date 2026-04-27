/**
 * Resolve the bind address for the self-hosted relay's HTTP/WS server.
 *
 * Rules (issue #1):
 *   - Explicit `--bind <addr>` always wins, in any mode.
 *   - With `--tailscale` and no explicit bind: default to `127.0.0.1`.
 *     `tailscale serve` proxies tailnet traffic to `127.0.0.1:<port>`,
 *     so loopback is sufficient and removes the inadvertent LAN exposure.
 *   - Without `--tailscale` and no explicit bind: return undefined to
 *     preserve the historical all-interfaces (`0.0.0.0`) listen behavior
 *     for users who deliberately expose the daemon on a LAN.
 */
export function resolveBindHost(opts: {
  explicit: string | null;
  tailscale: boolean;
}): string | undefined {
  if (opts.explicit) return opts.explicit;
  if (opts.tailscale) return "127.0.0.1";
  return undefined;
}
