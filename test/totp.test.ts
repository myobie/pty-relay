import { describe, it, expect } from "vitest";
import {
  base32Encode,
  base32Decode,
  generateTotpCode,
  generateTotpSecret,
  generateConsecutiveCodes,
  otpauthUrl,
  secondsUntilNextStep,
} from "../src/crypto/totp.ts";

describe("base32", () => {
  it("round-trips arbitrary bytes", () => {
    const src = new Uint8Array(20);
    for (let i = 0; i < 20; i++) src[i] = (i * 17 + 5) & 0xff;
    const encoded = base32Encode(src);
    const decoded = base32Decode(encoded);
    expect(Array.from(decoded)).toEqual(Array.from(src));
  });

  it("encodes ASCII '12345678901234567890' to the known base32", () => {
    // RFC 6238 Appendix B secret. Matches Elixir `Base.encode32/2`.
    const ascii = new TextEncoder().encode("12345678901234567890");
    expect(base32Encode(ascii)).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
  });

  it("tolerates padding and lowercase on decode", () => {
    const pad = base32Decode("gezdgnbvgy3tqojqgezdgnbvgy3tqojq====");
    expect(pad.length).toBe(20);
    expect(new TextDecoder().decode(pad)).toBe("12345678901234567890");
  });

  it("throws on invalid base32 character", () => {
    expect(() => base32Decode("AB!CD")).toThrow(/invalid character/);
  });
});

describe("generateTotpSecret", () => {
  it("returns 20 bytes", () => {
    expect(generateTotpSecret().length).toBe(20);
  });

  it("returns different bytes each call", () => {
    const a = generateTotpSecret();
    const b = generateTotpSecret();
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });
});

// RFC 6238 Appendix B test vectors, SHA-1 variant.
// Secret = ASCII "12345678901234567890" (20 bytes).
// The RFC prints 8-digit codes; 6-digit is the same number mod 10^6
// (i.e. the trailing 6 digits).
describe("generateTotpCode — RFC 6238 Appendix B vectors", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // base32("12345678901234567890")

  const vectors: Array<{ time: number; code: string }> = [
    { time: 59, code: "287082" },
    { time: 1111111109, code: "081804" },
    { time: 1111111111, code: "050471" },
    { time: 1234567890, code: "005924" },
    { time: 2000000000, code: "279037" },
    // 20000000000 exceeds signed-32-bit — covers the high-word path of
    // the 8-byte counter encoding.
    { time: 20000000000, code: "353130" },
  ];

  for (const { time, code } of vectors) {
    it(`time=${time} → ${code}`, () => {
      expect(generateTotpCode(secret, time)).toBe(code);
    });
  }
});

describe("generateConsecutiveCodes", () => {
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

  it("returns two distinct codes 30 seconds apart", () => {
    const [c1, c2] = generateConsecutiveCodes(secret, 59);
    expect(c1).toBe("287082");
    // At t=89 (59+30), counter = floor(89/30) = 2, same counter as t=60..89.
    // The RFC has no vector for t=89 directly, so we just assert consistency
    // with a second call at that timestamp.
    expect(c2).toBe(generateTotpCode(secret, 89));
    expect(c1).not.toBe(c2);
  });
});

describe("otpauthUrl", () => {
  it("builds an authenticator-compatible URL with issuer prefix", () => {
    const url = otpauthUrl("GEZDGNBVGY3TQOJQ", "me@example.com", "pty-relay");
    expect(url).toBe(
      "otpauth://totp/pty-relay%3Ame%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=pty-relay"
    );
  });

  it("defaults issuer to pty-relay", () => {
    expect(otpauthUrl("S", "a@b.com")).toContain("issuer=pty-relay");
  });
});

describe("secondsUntilNextStep", () => {
  it("returns the remainder to the next 30s boundary", () => {
    expect(secondsUntilNextStep(0)).toBe(30);
    expect(secondsUntilNextStep(1)).toBe(29);
    expect(secondsUntilNextStep(29)).toBe(1);
    expect(secondsUntilNextStep(30)).toBe(30);
    expect(secondsUntilNextStep(45)).toBe(15);
  });
});
