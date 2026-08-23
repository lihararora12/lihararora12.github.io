import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scanner } from "../src/lib/secret-scanner/scanner.ts";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

async function walk(directory: string): Promise<string[]> {
  const entries = await readdir(directory, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries) {
    const current = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...await walk(current));
    else files.push(current);
  }
  return files;
}

await scanner.loadDetectors();
const audit = scanner.auditDetectors();
assert.equal(audit.detectorCount, 112, "Unexpected detector count");
assert.equal(audit.patternCount, 141, "Unexpected detector-pattern count");
assert.deepEqual(audit.detectorsWithoutPatterns, [], "A detector has no pattern");
assert.deepEqual(audit.invalidPatterns, [], "A detector contains an invalid browser regex");

const cases: Array<[string, string, string]> = [
  ["Cloud", "aws_access_key", `AWS_ACCESS_KEY=${"AKIA" + "Q7W8E9R0T1Y2U3I4"}`],
  ["DevTools", "github_pat", `GITHUB_TOKEN=${"ghp_" + "Ab3d".repeat(9)}`],
  ["Communication", "slack_bot_token", `SLACK_TOKEN=xoxb-${"1".repeat(10)}-${"2".repeat(10)}-${"Ab".repeat(12)}`],
  ["AI/ML", "openai_api_key", `OPENAI_API_KEY=${"sk-proj-" + "Ab3d".repeat(15)}`],
  ["Payments", "stripe_secret_key", `STRIPE_SECRET_KEY=${"sk_live_" + "Ab3d".repeat(6)}`],
  ["Database", "mongodb_atlas_uri", ["DATABASE_URL=mongodb+srv://", "demo", ":", "password", "@cluster.mongodb.net"].join("")],
  ["Monitoring", "datadog_api_key", `DD_API_KEY=ddapikey_${"a1".repeat(16)}`],
  ["IAM", "okta_api_token", `OKTA_TOKEN=${"00" + "Ab3d".repeat(10)}`],
  ["Social", "twitter_bearer_token", `TWITTER_BEARER=${"A".repeat(21) + "Bc3d".repeat(20)}`],
  ["Search", "mapbox_token", `MAPBOX_TOKEN=${"pk.eyJ1" + "Ab3d".repeat(15)}`],
  ["CRM", "hubspot_api_key", ["HUBSPOT_TOKEN=pat-na-", "12345678", "-1234-1234-1234-", "123456789abc"].join("")],
  ["Storage", "cloudinary_url", ["CLOUDINARY_URL=cloudinary://", "demoUser", ":", "demoSecret", "@examplecloud"].join("")],
  ["Media", "pexels_api_key", `PEXELS_KEY=${"Ab3d".repeat(14)} pexels`],
  ["Certificates", "private_key_rsa", ["-----BEGIN", "PRIVATE KEY-----"].join(" ")],
  ["Generic", "generic_api_key", `api_key=${"Ab3d".repeat(8)}`],
  ["Data Science", "kaggle_api_token", `KAGGLE_KEY=${"KGAT_" + "a1".repeat(16)}`],
];

for (const [category, serviceType, input] of cases) {
  const results = scanner.scan(input, "synthetic-test.env");
  assert.ok(results.some(result => result.serviceType === serviceType), `${category} sample missed by ${serviceType}`);
}

assert.deepEqual(
  [...new Set(cases.map(([category]) => category))].sort(),
  [...new Set(scanner.getDetectors().map(detector => detector.category))].sort(),
  "Representative samples do not cover every detector category",
);

const contextSample = scanner.scan(`NODE_ENV=production\nGITHUB_TOKEN=${"ghp_" + "Bc4e".repeat(9)}`, ".env.production")[0];
assert.equal(contextSample.environment, "Production");
assert.equal(contextSample.variableName, "GITHUB_TOKEN");
assert.equal(contextSample.context.matched.includes(contextSample.secret), false, "Redacted context leaked a credential");

const publicFiles = (await Promise.all([
  walk(path.join(root, "src")),
  walk(path.join(root, "public")),
  walk(path.join(root, ".github")),
])).flat().filter(file =>
  /\.(?:astro|md|js|ts|tsx|json|ya?ml|xml|txt|svg)$/.test(file) && !file.includes(`${path.sep}lib${path.sep}secret-scanner${path.sep}`),
);

const accidentalFindings: string[] = [];
for (const file of publicFiles) {
  const contents = await readFile(file, "utf8");
  const findings = scanner.scan(contents, path.relative(root, file));
  if (findings.length) accidentalFindings.push(`${path.relative(root, file)}: ${findings.map(finding => finding.displayName).join(", ")}`);
}
assert.deepEqual(accidentalFindings, [], `Potential credentials found in public source:\n${accidentalFindings.join("\n")}`);

console.log(`Scanner verified: ${audit.detectorCount} detectors, ${audit.patternCount} patterns, ${cases.length} categories, and no credentials in public source.`);
