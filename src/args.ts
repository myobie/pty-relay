/** Extract all `--tag key=value` pairs from argv (repeatable).
 *  Matches the shape of `@myobie/pty/client`'s `extractFilterTags`:
 *  same `key=value` contract, but for `--tag` (which `pty run` also uses).
 *  Exits the process with code 1 on a malformed pair so the user sees
 *  the error instead of the daemon silently dropping bad input. */
export function extractTagFlags(argList: string[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (let i = 0; i < argList.length; i++) {
    if (argList[i] !== "--tag") continue;
    const kv = argList[i + 1];
    if (!kv || !kv.includes("=")) {
      console.error(`--tag expects "key=value"`);
      process.exit(1);
    }
    const eq = kv.indexOf("=");
    out[kv.slice(0, eq)] = kv.slice(eq + 1);
    i++;
  }
  return out;
}
