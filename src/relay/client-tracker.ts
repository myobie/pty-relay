export interface ClientMeta {
  client: string;  // "cli" | "web" | "ios" | "android"
  os: string;
  label: string;
  connectedAt: Date;
}

/**
 * Tracks metadata about the currently connected client.
 * This information comes through the encrypted tunnel —
 * the relay never sees it.
 */
export class ClientTracker {
  private current: ClientMeta | null = null;

  setClient(meta: { client?: string; os?: string; label?: string }): void {
    this.current = {
      client: meta.client || "unknown",
      os: meta.os || "unknown",
      label: meta.label || "",
      connectedAt: new Date(),
    };
  }

  clearClient(): void {
    this.current = null;
  }

  getClient(): ClientMeta | null {
    return this.current;
  }
}
