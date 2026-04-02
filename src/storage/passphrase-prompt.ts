/**
 * Read a passphrase from the TTY with echoed stars.
 *
 * Writes prompts to stderr so stdout stays clean for command output.
 * Throws if stdin is not a TTY.
 */
export async function readPassphrase(opts?: {
  prompt?: string;
  confirm?: boolean;
}): Promise<string> {
  if (!process.stdin.isTTY) {
    throw new Error(
      "passphrase prompt requires a TTY; set PTY_RELAY_PASSPHRASE or use --passphrase-file"
    );
  }

  const promptText = opts?.prompt ?? "Passphrase: ";

  const first = await readOne(promptText);
  if (!opts?.confirm) return first;

  const second = await readOne("Confirm passphrase: ");
  if (first !== second) {
    throw new Error("passphrases do not match");
  }
  return first;
}

function readOne(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    const stderr = process.stderr;

    stderr.write(prompt);

    const wasRaw = stdin.isRaw;
    try {
      stdin.setRawMode?.(true);
    } catch (err) {
      reject(err as Error);
      return;
    }
    stdin.resume();
    stdin.setEncoding("utf8");

    let buf = "";

    const cleanup = () => {
      stdin.removeListener("data", onData);
      try {
        stdin.setRawMode?.(wasRaw ?? false);
      } catch {}
      stdin.pause();
    };

    const onData = (chunk: string) => {
      for (const ch of chunk) {
        // Enter
        if (ch === "\r" || ch === "\n") {
          stderr.write("\n");
          cleanup();
          resolve(buf);
          return;
        }
        // Ctrl+C
        if (ch === "\u0003") {
          stderr.write("\n");
          cleanup();
          reject(new Error("passphrase entry cancelled"));
          return;
        }
        // Backspace / DEL
        if (ch === "\u007f" || ch === "\b") {
          if (buf.length > 0) {
            buf = buf.slice(0, -1);
            stderr.write("\b \b");
          }
          continue;
        }
        // Ignore any other control chars
        if (ch < " ") continue;

        buf += ch;
        stderr.write("*");
      }
    };

    stdin.on("data", onData);
  });
}
