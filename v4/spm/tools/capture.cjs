const { chromium } = require("playwright");
const { execFileSync, spawn } = require("node:child_process");
const { mkdtempSync, mkdirSync, rmSync } = require("node:fs");
const { tmpdir } = require("node:os");
const { join } = require("node:path");
const assert = require("node:assert/strict");

const directory = mkdtempSync(join(tmpdir(), "spm-capture-"));
const db = join(directory, "capture.sqlite");
const output = process.argv[2];
const cli = join(__dirname, "../app.py");
const python = process.env.SPM_PYTHON || "python3";
const token = execFileSync(python, [cli, "--db", db, "issue", "Model Operations", "Jules", "admin"], { encoding: "utf8" }).trim();
const server = spawn(python, [cli, "--db", db, "serve", "--port", "0"], { stdio: ["ignore", "pipe", "inherit"] });

async function capture() {
  const origin = await new Promise((resolve, reject) => {
    server.stdout.once("data", (chunk) => {
      const address = chunk.toString().match(/http:\/\/127\.0\.0\.1:\d+/)?.[0];
      if (address) resolve(address);
      else reject(Error("Server address missing"));
    });
    server.once("error", reject);
    server.once("exit", (code) => reject(Error("Server exited: " + code)));
  });
  const browser = await chromium.launch({ executablePath: process.env.SPM_CHROME });
  try {
    mkdirSync(output, { recursive: true });
    const page = await browser.newPage({ viewport: { width: 1120, height: 780 } });
    const shot = async (name) => page.screenshot({ path: join(output, name + ".png") });
    await page.goto(origin);
    assert.equal((await page.request.get(origin + "/health")).status(), 200);
    assert.equal((await page.request.get(origin + "/api/v1/assets")).status(), 401);
    await shot("connect");
    await page.getByLabel("Access token").fill(token);
    await page.getByRole("button", { name: "Connect" }).click();
    await page.getByRole("heading", { name: "Asset inventory" }).waitFor();
    await page.getByLabel("Asset ID").fill("training-store");
    await page.getByLabel("Encrypted at rest").selectOption("false");
    await page.getByLabel("Public access").selectOption("false");
    await shot("inventory");
    await page.getByRole("button", { name: "Save asset" }).click();
    await page.getByRole("button", { name: "Run assessment" }).click();
    await page.getByText("Complete coverage · posture score 70/100").waitFor();
    await shot("report");
    await page.getByRole("button", { name: "Open report" }).click();
    await page.getByText("Enable encryption at rest", { exact: false }).waitFor();
    await page.getByRole("button", { name: "Audit log" }).click();
    await page.getByText("scan.completed", { exact: false }).waitFor();
    await shot("audit");
    await page.getByRole("button", { name: "API console" }).click();
    await page.getByRole("button", { name: "Send GET request" }).click();
    await page.getByText("HTTP 200", { exact: false }).waitFor();
    await shot("api");
    await page.getByRole("button", { name: "Sign out" }).click();
    await page.getByRole("heading", { name: "Open your project" }).waitFor();
    console.log("HTTP, browser sign-in, asset entry, scan, report retrieval, audit, API console and sign-out passed.");
  } finally {
    await browser.close();
  }
}

capture().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
}).finally(() => {
  server.kill();
  server.once("close", () => rmSync(directory, { recursive: true, force: true }));
});
