// Actions by an outside party (key R): send ETH or WETH to an address, to simulate "receive".
// Usage: tsx driver/external.ts eth <to> <amount> | weth <to> <amount>
import { readFileSync } from "node:fs";
import { createPublicClient, createWalletClient, http, parseEther, parseAbi } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia } from "viem/chains";
const WETH = "0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14";
const RPC = process.env.SIGNER_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com";
const keys = JSON.parse(readFileSync("secrets/keys.json", "utf8"));
const acct = privateKeyToAccount(keys[process.env.FROM ?? "R"].pk);
const pub = createPublicClient({ chain: sepolia, transport: http(RPC) });
const w = createWalletClient({ account: acct, chain: sepolia, transport: http(RPC) });
const [, , kind, to, amt] = process.argv;
const abi = parseAbi(["function deposit() payable", "function transfer(address,uint256) returns (bool)"]);
let h;
if (kind === "eth") h = await w.sendTransaction({ to: to as any, value: parseEther(amt) });
else {
  h = await w.writeContract({ address: WETH, abi, functionName: "deposit", value: parseEther(amt) });
  await pub.waitForTransactionReceipt({ hash: h });
  h = await w.writeContract({ address: WETH, abi, functionName: "transfer", args: [to as any, parseEther(amt)] });
}
await pub.waitForTransactionReceipt({ hash: h });
console.log(kind, amt, h);
