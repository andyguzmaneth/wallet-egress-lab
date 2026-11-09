// Create the MetaMask lab recovery phrase (once) and fund its accounts on Sepolia from FUNDER_KEY.
// The phrase is generated here for this lab only. Accounts: A = index 0, B = index 1 (m/44'/60'/0'/0/i).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, createWalletClient, http, parseEther, formatEther } from "viem";
import { english, generateMnemonic, mnemonicToAccount, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

const PATH = "secrets/metamask.json";
const RPC = process.env.SIGNER_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";
if (!existsSync(PATH)) {
  const mnemonic = generateMnemonic(english);
  const acct = (i: number) => ({ address: mnemonicToAccount(mnemonic, { addressIndex: i }).address });
  writeFileSync(PATH, JSON.stringify({ mnemonic, A: acct(0), B: acct(1) }, null, 2), { mode: 0o600 });
}
const keys = JSON.parse(readFileSync(PATH, "utf8"));
const pub = createPublicClient({ chain: sepolia, transport: http(RPC) });
if (process.argv[2] === "fund") {
  const funder = privateKeyToAccount(process.env.FUNDER_KEY as `0x${string}`);
  const w = createWalletClient({ account: funder, chain: sepolia, transport: http(RPC) });
  for (const [n, amt] of [["A", "0.1"], ["B", "0.02"]]) {
    const h = await w.sendTransaction({ to: keys[n].address, value: parseEther(amt) });
    await pub.waitForTransactionReceipt({ hash: h });
    console.log("funded", n, amt, h);
  }
}
for (const n of ["A", "B"]) console.log(n, keys[n].address, formatEther(await pub.getBalance({ address: keys[n].address })));
