import { createHash, createCipheriv, generateKeyPairSync } from "crypto";

export function keys() {
  return generateKeyPairSync("rsa", {
    modulusLength: 3072,
  });
}

export const etag = (s: string) => createHash("sha1").update(s).digest("hex");
export const enc = (k: Buffer, iv: Buffer) => createCipheriv("aes-256-gcm", k, iv);
