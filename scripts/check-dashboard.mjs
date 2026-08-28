import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const baseURL = process.argv[2] ?? "http://127.0.0.1:3000";
const outputDirectory = resolve(process.argv[3] ?? "tmp/p5-dashboard");
await mkdir(outputDirectory, { recursive: true });

const executablePath = [
  process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE,
  chromium.executablePath(),
  process.env["ProgramFiles(x86)"] ? join(process.env["ProgramFiles(x86)"], "Microsoft", "Edge", "Application", "msedge.exe") : undefined,
].find((candidate) => candidate && existsSync(candidate));
const browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 1 });
const pageErrors = [];
page.on("pageerror", (error) => pageErrors.push(error.message));

try {
  await open(page, "/");
  await expectText(page, "h2", "Overview");
  await expectText(page, "body", "P5 acceptance fixture");
  await page.screenshot({ path: resolve(outputDirectory, "overview.png"), fullPage: true });

  await page.getByRole("link", { name: /P5 acceptance fixture/ }).click();
  await page.waitForURL(/\/evidence\/run-demo$/);
  await expectText(page, "h2", "Evidence detail");
  await expectCount(page, ".evidence-event", 6);
  await expectText(page, "body", "Attempt observed");
  await expectText(page, "body", "No completion outcome was observed.");
  await expectText(page, "body", "matched · 99/100");
  await expectText(page, "body", "Kernel block observed");
  await expectText(page, "body", "killed");
  await page.screenshot({ path: resolve(outputDirectory, "evidence-desktop.png"), fullPage: true });

  await open(page, "/policies");
  await expectText(page, "h2", "Policies");
  await expectCount(page, "tbody tr", 3);
  await expectText(page, "body", "builtin.net.outbound-observe");

  await open(page, "/diagnostics");
  await expectText(page, "h2", "Diagnostics");
  await expectText(page, "body", "Actual load/attach probe: unknown");
  await expectText(page, "body", "deterministic dashboard replay is active; no kernel claim is made");

  await open(page, "/live-trace");
  await page.locator('input[type="checkbox"]').check();
  await page.getByRole("button", { name: "Apply filters" }).click();
  await page.locator(".page-header .pill").filter({ hasText: "live" }).waitFor({ timeout: 10_000 });
  await page.locator(".trace-row").first().waitFor({ timeout: 10_000 });
  await page.screenshot({ path: resolve(outputDirectory, "live-trace.png"), fullPage: true });

  await page.setViewportSize({ width: 390, height: 844 });
  await open(page, "/evidence/run-demo");
  await expectCount(page, ".evidence-event", 6);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  if (overflow > 1) throw new Error(`mobile layout overflows horizontally by ${overflow}px`);
  await page.screenshot({ path: resolve(outputDirectory, "evidence-mobile.png"), fullPage: true });

  if (pageErrors.length > 0) throw new Error(`browser page errors: ${pageErrors.join(" | ")}`);
  console.log(`P5 dashboard browser acceptance passed; screenshots: ${outputDirectory}`);
} finally {
  await browser.close();
}

async function open(page, path) {
  const response = await page.goto(new URL(path, baseURL).toString(), { waitUntil: "domcontentloaded", timeout: 60_000 });
  if (!response?.ok()) throw new Error(`${path} returned HTTP ${response?.status() ?? "unknown"}`);
  await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => undefined);
  await page.locator("main").waitFor({ timeout: 10_000 });
}

async function expectText(page, selector, text) {
  await page.locator(selector).filter({ hasText: text }).first().waitFor({ timeout: 10_000 });
}

async function expectCount(page, selector, count) {
  await page.waitForFunction(({ selector, count }) => document.querySelectorAll(selector).length === count, { selector, count }, { timeout: 10_000 });
}
