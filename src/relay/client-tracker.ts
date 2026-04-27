import { log } from "../log.ts";

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
    log("serve", "client hello", {
      client: this.current.client,
      os: this.current.os,
      label: this.current.label,
    });
  }

  clearClient(): void {
    if (this.current) log("serve", "client tracker cleared");
    this.current = null;
  }

  getClient(): ClientMeta | null {
    return this.current;
  }
}
