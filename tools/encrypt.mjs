// Encrypts the CV PDF into cv.enc (AES-256-GCM) and prints the access URL.
//
// Usage: node tools/encrypt.mjs [path/to/cv.pdf]
//
// Output format of cv.enc: 12-byte IV || ciphertext+tag.
// A fresh random key is generated on every run, which revokes all previous URLs.

import { readFile, writeFile } from "node:fs/promises";
import { webcrypto as crypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const input = process.argv[2] ?? path.join(root, "cv.pdf");
const BASE_URL = "https://jduc.github.io/";

const pdf = await readFile(input);
if (pdf.subarray(0, 5).toString() !== "%PDF-") {
  console.error(`${input} does not look like a PDF`);
  process.exit(1);
}

const rawKey = crypto.getRandomValues(new Uint8Array(32));
const iv = crypto.getRandomValues(new Uint8Array(12));
const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt"]);
const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pdf));

await writeFile(path.join(root, "cv.enc"), Buffer.concat([iv, ciphertext]));

const url = `${BASE_URL}#${Buffer.from(rawKey).toString("base64url")}`;
await writeFile(path.join(root, "cv.url"), url + "\n");

console.log(`Encrypted ${input} -> cv.enc (${ciphertext.length + iv.length} bytes)`);
console.log(`URL (also saved to cv.url, gitignored):\n${url}`);
