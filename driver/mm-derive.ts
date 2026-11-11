// Derive the non-EVM addresses MetaMask creates from the lab phrase (multichain accounts, 13.56),
// so the analysis can search the capture for them. Derived here from the phrase, not read from the
// capture, so finding them in the traffic is an independent check. Each EVM account (A = 0, B = 1) gets
// a Bitcoin, Solana, Tron and Stellar account at the same account index.
// Usage: tsx driver/mm-derive.ts [secrets/metamask.json]   prints JSON {label: value}
import { readFileSync } from "node:fs";
import { mnemonicToSeedSync } from "@scure/bip39";
import { HDKey } from "@scure/bip32";
import { bech32, base58, base58check, base32 } from "@scure/base";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { hmac } from "@noble/hashes/hmac";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { keccak_256 } from "@noble/hashes/sha3";

const { mnemonic } = JSON.parse(readFileSync(process.argv[2] ?? "secrets/metamask.json", "utf8"));
const seed = mnemonicToSeedSync(mnemonic);
const root = HDKey.fromMasterSeed(seed);
const hex = (b: Uint8Array) => Buffer.from(b).toString("hex");

// SLIP-10 ed25519 (hardened only), for Solana and Stellar.
function slip10(path: number[]): Uint8Array {
  let I = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed);
  for (const i of path) {
    const data = new Uint8Array(37);
    data.set(I.slice(0, 32), 1);
    new DataView(data.buffer).setUint32(33, (i | 0x80000000) >>> 0);
    I = hmac(sha512, I.slice(32), data);
  }
  return I.slice(0, 32);
}
function crc16(b: Uint8Array) {
  let c = 0;
  for (const x of b) { c ^= x << 8; for (let i = 0; i < 8; i++) c = c & 0x8000 ? ((c << 1) ^ 0x1021) & 0xffff : (c << 1) & 0xffff; }
  return c;
}

const out: Record<string, string> = {};
for (const [n, acct] of [["A", 0], ["B", 1]] as const) {
  // Bitcoin native segwit (BIP-84). Esplora is queried by script hash (sha256 of the output script),
  // over the first receive and change addresses, so list those too.
  const p2wpkh = (ch: number, i: number) => ripemd160(sha256(root.derive(`m/84'/0'/${acct}'/${ch}/${i}`).publicKey!));
  out[`${n} bitcoin`] = bech32.encode("bc", [0, ...bech32.toWords(p2wpkh(0, 0))]);
  for (const ch of [0, 1]) for (let i = 0; i < 10; i++)
    out[`${n} bitcoin scripthash ${ch}/${i}`] = hex(sha256(new Uint8Array([0x00, 0x14, ...p2wpkh(ch, i)])));
  // Tron: secp256k1 at m/44'/195'/0'/0/<index> (the index is the last level here), keccak of the
  // uncompressed key, 0x41 prefix, base58check.
  const trx = secp256k1.getPublicKey(root.derive(`m/44'/195'/0'/0/${acct}`).privateKey!, false).slice(1);
  out[`${n} tron`] = base58check(sha256).encode(new Uint8Array([0x41, ...keccak_256(trx).slice(-20)]));
  out[`${n} solana`] = base58.encode(ed25519.getPublicKey(slip10([44, 501, acct, 0])));
  // Stellar strkey: version byte 6<<3, key, CRC16-XModem little-endian, base32 without padding.
  const body = new Uint8Array([6 << 3, ...ed25519.getPublicKey(slip10([44, 148, acct]))]);
  const crc = crc16(body);
  out[`${n} stellar`] = base32.encode(new Uint8Array([...body, crc & 0xff, crc >> 8])).replace(/=+$/, "");
}
console.log(JSON.stringify(out, null, 1));
