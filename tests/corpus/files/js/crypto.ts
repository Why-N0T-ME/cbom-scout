import { createHash, createCipheriv, createHmac, generateKeyPairSync } from "crypto";

// createHash('md5') 는 금지
/* createCipheriv('des-ede3-cbc', k, iv) */
const s = "createHash('sha1')";
const t = `createHash('sha1')`;
const sha1Label = "sha1";

export function run(k: Buffer, iv: Buffer) {
  const a = createHash('md5');
  const b = createHash('sha256');
  const c = createCipheriv('aes-256-gcm', k, iv);
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 1024,
  });
  const m = createHmac('sha1', k);
  return [a, b, c, privateKey, m];
}
