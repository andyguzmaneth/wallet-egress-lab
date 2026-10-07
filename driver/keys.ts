// Create the lab owner keys (once) and fund them on Sepolia from FUNDER_KEY.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createPublicClient, createWalletClient, http, parseEther, formatEther } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";

const PATH = "secrets/keys.json";
const RPC = process.env.SIGNER_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";
if (!existsSync(PATH)) {
  const keys = Object.fromEntries(["A", "B", "C", "R"].map((n) => {
    const pk = generatePrivateKey();
    return [n, { pk, address: privateKeyToAccount(pk).address }];
  }));
  writeFileSync(PATH, JSON.stringify(keys, null, 2), { mode: 0o600 });
}
const keys = JSON.parse(readFileSync(PATH, "utf8"));
const pub = createPublicClient({ chain: sepolia, transport: http(RPC) });
if (process.argv[2] === "fund") {
  const funder = privateKeyToAccount(process.env.FUNDER_KEY as `0x${string}`);
  const w = createWalletClient({ account: funder, chain: sepolia, transport: http(RPC) });
  for (const [n, amt] of [["A", "0.25"], ["B", "0.05"], ["R", "0.1"]]) {
    const h = await w.sendTransaction({ to: keys[n].address, value: parseEther(amt) });
    await pub.waitForTransactionReceipt({ hash: h });
    console.log("funded", n, amt, h);
  }
}
for (const [n, k] of Object.entries<any>(keys)) console.log(n, k.address, formatEther(await pub.getBalance({ address: k.address })));
