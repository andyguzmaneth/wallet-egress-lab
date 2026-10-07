// Injected EIP-1193 signer. The page sees an ordinary injected wallet ("Lab Signer").
// All key material and the signer's own RPC stay in Node, outside the proxied browser,
// so the capture only holds traffic that the wallet app itself makes.
import type { BrowserContext } from "playwright";
import { createPublicClient, createWalletClient, http, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { sepolia, mainnet } from "viem/chains";
import { appendFileSync } from "node:fs";

const INJECT = `(() => {
  const listeners = {};
  const provider = {
    isMetaMask: false, isLabSigner: true,
    request: async ({ method, params }) => {
      const r = await window.__labSigner(JSON.stringify({ method, params }));
      const o = JSON.parse(r);
      if (o.error) { const e = new Error(o.error.message); e.code = o.error.code; throw e; }
      if (o.emit) for (const [ev, arg] of o.emit) (listeners[ev] || []).forEach((f) => f(arg));
      return o.result;
    },
    on: (ev, f) => { (listeners[ev] ||= []).push(f); return provider; },
    removeListener: (ev, f) => { listeners[ev] = (listeners[ev] || []).filter((x) => x !== f); return provider; },
  };
  provider.enable = () => provider.request({ method: "eth_requestAccounts" });
  window.ethereum = provider;
  const info = { uuid: "6f1a4c1e-0000-4000-8000-1ab5161e0001", name: "Lab Signer", rdns: "lab.signer",
    icon: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 1 1'%3E%3Crect width='1' height='1'/%3E%3C/svg%3E" };
  const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: Object.freeze({ info, provider }) }));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();
})();`;

export class Signer {
  chainId: number;
  sentTx = 0;
  signed = 0;
  account;
  constructor(private pk: Hex, chain: "sepolia" | "mainnet", private log: string, private readOnly = false) {
    this.chainId = chain === "sepolia" ? sepolia.id : mainnet.id;
    this.account = privateKeyToAccount(pk);
  }
  private clients() {
    const chain = this.chainId === sepolia.id ? sepolia : mainnet;
    const url = this.chainId === sepolia.id ? process.env.SIGNER_RPC ?? "https://ethereum-sepolia-rpc.publicnode.com"
      : process.env.SIGNER_RPC_MAINNET ?? "https://ethereum-rpc.publicnode.com";
    return { pub: createPublicClient({ chain, transport: http(url) }), wal: createWalletClient({ account: this.account, chain, transport: http(url) }), url };
  }
  setKey(pk: Hex) { this.pk = pk; this.account = privateKeyToAccount(pk); }
  async install(ctx: BrowserContext) {
    await ctx.exposeFunction("__labSigner", async (raw: string) => {
      const { method, params } = JSON.parse(raw);
      const t = Date.now();
      let out: any;
      try { out = await this.handle(method, params ?? []); } catch (e: any) { out = { error: { code: e.code ?? -32603, message: String(e.shortMessage ?? e.message) } }; }
      appendFileSync(this.log, JSON.stringify({ t: t / 1000, ms: Date.now() - t, method, params, error: out.error?.message }) + "\n");
      return JSON.stringify(out);
    });
    await ctx.addInitScript(INJECT);
  }
  private async handle(method: string, params: any[]): Promise<any> {
    const { pub, wal } = this.clients();
    const hexChain = "0x" + this.chainId.toString(16);
    switch (method) {
      case "eth_requestAccounts": case "eth_accounts": return { result: [this.account.address] };
      case "eth_chainId": return { result: hexChain };
      case "net_version": return { result: String(this.chainId) };
      case "wallet_switchEthereumChain": {
        const want = parseInt(params[0].chainId, 16);
        if (want !== this.chainId) return { error: { code: 4902, message: "chain not available in lab signer" } };
        return { result: null };
      }
      case "wallet_requestPermissions": case "wallet_getPermissions": return { result: [{ parentCapability: "eth_accounts" }] };
      case "personal_sign": {
        if (this.readOnly) return { error: { code: 4001, message: "read-only pass" } };
        const [msg] = params;
        return { result: await this.account.signMessage({ message: /^0x[0-9a-fA-F]*$/.test(msg) ? { raw: msg as Hex } : msg }) };
      }
      case "eth_signTypedData_v4": case "eth_signTypedData": {
        if (this.readOnly) return { error: { code: 4001, message: "read-only pass" } };
        const td = typeof params[1] === "string" ? JSON.parse(params[1]) : params[1];
        const { EIP712Domain, ...types } = td.types;
        this.signed++;
        const domain = { ...td.domain, ...(td.domain.chainId !== undefined ? { chainId: Number(td.domain.chainId) } : {}) };
        return { result: await this.account.signTypedData({ domain, types, primaryType: td.primaryType, message: td.message }) };
      }
      case "eth_sendTransaction": {
        if (this.readOnly) return { error: { code: 4001, message: "read-only pass" } };
        const tx = params[0];
        const h = await wal.sendTransaction({ to: tx.to, data: tx.data, value: tx.value ? BigInt(tx.value) : undefined,
          gas: tx.gas ? BigInt(tx.gas) : undefined });
        this.sentTx++;
        return { result: h };
      }
      default: {
        const r = await pub.request({ method: method as any, params: params as any });
        return { result: r };
      }
    }
  }
}
