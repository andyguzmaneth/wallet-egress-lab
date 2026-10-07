import { chromium } from "playwright";
const [, , file, out, theme = "light", width = "1200"] = process.argv;
const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: Number(width), height: 900 }, colorScheme: theme as any });
await p.goto("file://" + file);
await p.screenshot({ path: out, fullPage: true });
const ov = await p.evaluate(() => document.documentElement.scrollWidth > innerWidth);
console.log("horizontal overflow:", ov, "height:", await p.evaluate(() => document.body.scrollHeight));
await b.close();
