// Minimal type shims for the vendored xterm.js modules.
//
// We load @xterm/xterm and @xterm/addon-fit via an importmap at runtime
// from /vendor/*.mjs, and esbuild is configured to treat those specifiers
// as external so the importmap resolves them in the browser. These shims
// exist only so the TypeScript compiler has something to type-check
// against during the bundle step — they're not complete or authoritative.

declare module "@xterm/xterm" {
  export interface ITerminalOptions {
    cursorBlink?: boolean;
    fontSize?: number;
    smoothScrollDuration?: number;
    theme?: { background?: string };
  }

  export interface ITerminalDimensions {
    cols: number;
    rows: number;
  }

  export class Terminal {
    readonly cols: number;
    readonly rows: number;
    constructor(options?: ITerminalOptions);
    loadAddon(addon: unknown): void;
    open(parent: HTMLElement): void;
    write(data: string | Uint8Array): void;
    focus(): void;
    dispose(): void;
    scrollLines(amount: number): void;
    onResize(cb: (dims: ITerminalDimensions) => void): void;
    onData(cb: (data: string) => void): void;
  }
}

declare module "@xterm/addon-fit" {
  export class FitAddon {
    constructor();
    fit(): void;
  }
}
