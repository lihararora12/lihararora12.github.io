import { DETECTORS } from "./detectors.ts";

export type Confidence = "high" | "medium" | "low";
export type RiskLevel = "critical" | "high" | "medium" | "low";

export interface DetectorPattern {
  name: string;
  serviceType: string;
  tokenType: string;
  category: string;
  color: string;
  patterns: RegExp[];
  description: string;
  defaultConfidence: Confidence;
}

export interface ScanContext {
  before: string[];
  matched: string;
  after: string[];
}

export interface ScanResult {
  id: string;
  detector: string;
  displayName: string;
  serviceType: string;
  tokenType: string;
  category: string;
  color: string;
  secret: string;
  position: number;
  line: number;
  column: number;
  confidence: Confidence;
  risk: RiskLevel;
  riskScore: number;
  riskReasons: string[];
  description: string;
  variableName?: string;
  environment: "Production" | "Development" | "Test / example" | "Unknown";
  exposure: string;
  sourceName: string;
  context: ScanContext;
  recommendation: {
    title: string;
    steps: string[];
  };
}

export interface DetectorAudit {
  detectorCount: number;
  patternCount: number;
  invalidPatterns: Array<{ detector: string; pattern: string; error: string }>;
  detectorsWithoutPatterns: string[];
}

interface DetectionCandidate extends ScanResult {
  patternLength: number;
  detectorPriority: number;
}

const MAX_RESULTS = 500;

function clamp(value: number, minimum: number, maximum: number) {
  return Math.min(maximum, Math.max(minimum, value));
}

function maskMatch(line: string, secret: string) {
  return secret ? line.split(secret).join("[REDACTED]") : line;
}

function getRecommendation(detector: DetectorPattern) {
  const descriptor = `${detector.name} ${detector.tokenType} ${detector.category}`.toLowerCase();

  if (/private key|ssh|certificate/.test(descriptor)) {
    return {
      title: "Replace the key pair and remove it from history",
      steps: [
        "Generate a new key pair and update every authorized destination.",
        "Remove the exposed key from the current file and repository history.",
        "Review authentication logs for use of the old fingerprint.",
      ],
    };
  }
  if (/database|postgres|mysql|mongo|redis|connection/.test(descriptor)) {
    return {
      title: "Rotate the database credential and limit its reach",
      steps: [
        "Create a replacement credential with the minimum required permissions.",
        "Update the application through a secret manager or protected environment variable.",
        "Revoke the exposed credential and review recent connection activity.",
      ],
    };
  }
  if (/github|gitlab|source control|personal access/.test(descriptor)) {
    return {
      title: "Revoke the token and inspect repository activity",
      steps: [
        "Revoke the exposed token from the provider immediately.",
        "Create a narrowly scoped replacement only if the integration still needs one.",
        "Review commits, workflow runs, and audit logs since the likely exposure time.",
      ],
    };
  }
  if (/cloud|aws|azure|google cloud|digitalocean|cloudflare/.test(descriptor)) {
    return {
      title: "Rotate the cloud credential and review its permissions",
      steps: [
        "Disable or rotate the exposed credential before investigating further.",
        "Review IAM permissions and reduce them to the minimum required scope.",
        "Check provider audit logs for unexpected access or resource changes.",
      ],
    };
  }
  return {
    title: "Rotate the credential and move it to protected storage",
    steps: [
      "Revoke or rotate the exposed value at its issuing provider.",
      "Replace the plaintext value with a secret-manager or environment reference.",
      "Remove the value from version history and review recent usage logs.",
    ],
  };
}

export class SecretScanner {
  private detectors: DetectorPattern[] = [];

  async loadDetectors(): Promise<void> {
    this.detectors = DETECTORS.map(detector => ({
      name: detector.serviceName,
      serviceType: detector.serviceType,
      tokenType: detector.tokenType,
      category: detector.category,
      color: detector.color,
      patterns: detector.patterns.map(pattern => new RegExp(pattern.source, pattern.flags)),
      description: detector.description,
      defaultConfidence: detector.confidence,
    }));
  }

  scan(input: string, sourceName = "Pasted text"): ScanResult[] {
    if (!input.trim()) return [];

    const candidates: DetectionCandidate[] = [];
    const lines = input.split(/\r?\n/);
    const lineStarts = [0];
    for (let index = input.indexOf("\n"); index !== -1; index = input.indexOf("\n", index + 1)) {
      lineStarts.push(index + 1);
    }

    for (let detectorIndex = 0; detectorIndex < this.detectors.length; detectorIndex++) {
      const detector = this.detectors[detectorIndex];

      for (const pattern of detector.patterns) {
        const patternStr = pattern.source;
        if (this.isGenericPattern(patternStr) && !this.hasDetectorContext(input, detector)) continue;

        try {
          const flags = [...new Set(`${pattern.flags}g`)].join("");
          const regex = new RegExp(pattern.source, flags);
          let match: RegExpExecArray | null;

          while ((match = regex.exec(input)) !== null) {
            if (match[0].length === 0) regex.lastIndex += 1;

            let secret = match[0];
            for (let index = match.length - 1; index > 0; index--) {
              if (match[index]) {
                secret = match[index];
                break;
              }
            }

            const position = match.index + Math.max(0, match[0].indexOf(secret));
            const lineIndex = this.findLineIndex(lineStarts, position);
            const line = lineIndex + 1;
            const column = position - lineStarts[lineIndex] + 1;
            const nearby = lines.slice(Math.max(0, lineIndex - 2), lineIndex + 3).join("\n");
            const variableName = this.findVariableName(lines[lineIndex] ?? "", secret);
            const environment = this.inferEnvironment(sourceName, nearby);
            const exposure = this.inferExposure(sourceName, nearby);
            const confidence = this.calculateConfidence(secret, detector);
            const riskAssessment = this.assessRisk({ detector, confidence, environment, exposure, variableName, secret, nearby });

            candidates.push({
              id: `${detector.serviceType}-${position}-${secret.length}`,
              detector: detector.name,
              displayName: `${detector.name} · ${detector.tokenType}`,
              serviceType: detector.serviceType,
              tokenType: detector.tokenType,
              category: detector.category,
              color: detector.color,
              secret,
              position,
              line,
              column,
              confidence,
              risk: riskAssessment.risk,
              riskScore: riskAssessment.score,
              riskReasons: riskAssessment.reasons,
              description: detector.description,
              variableName,
              environment,
              exposure,
              sourceName,
              context: {
                before: lines.slice(Math.max(0, lineIndex - 2), lineIndex).map(value => maskMatch(value, secret)),
                matched: maskMatch(lines[lineIndex] ?? "", secret),
                after: lines.slice(lineIndex + 1, lineIndex + 3).map(value => maskMatch(value, secret)),
              },
              recommendation: getRecommendation(detector),
              patternLength: patternStr.length,
              detectorPriority: this.getDetectorPriority(detector),
            });

            if (candidates.length >= MAX_RESULTS) return this.finalize(candidates);
          }
        } catch {
          // Some upstream Go expressions are not valid JavaScript regexes.
        }
      }
    }

    return this.finalize(candidates);
  }

  private finalize(candidates: DetectionCandidate[]) {
    const results = this.deduplicateResults(candidates).sort((a, b) => b.riskScore - a.riskScore || a.position - b.position);
    const secrets = [...new Set(results.map(result => result.secret).filter(Boolean))];
    const redactLine = (line: string) => secrets.reduce((safe, secret) => safe.split(secret).join("[REDACTED]"), line);
    return results.map(result => ({
      ...result,
      context: {
        before: result.context.before.map(redactLine),
        matched: redactLine(result.context.matched),
        after: result.context.after.map(redactLine),
      },
    }));
  }

  private findLineIndex(lineStarts: number[], position: number) {
    let low = 0;
    let high = lineStarts.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (lineStarts[middle] <= position) low = middle + 1;
      else high = middle;
    }
    return Math.max(0, low - 1);
  }

  private findVariableName(line: string, secret: string) {
    const prefix = line.slice(0, Math.max(0, line.indexOf(secret)));
    return prefix.match(/(?:export\s+)?([A-Za-z_][\w.-]{2,})\s*(?:=|:)\s*["']?\s*$/)?.[1];
  }

  private inferEnvironment(sourceName: string, nearby: string): ScanResult["environment"] {
    const context = `${sourceName}\n${nearby}`.toLowerCase();
    if (/\.env\.prod|production|prod[_-]|release|live[_-]/.test(context)) return "Production";
    if (/test|spec|fixture|mock|sample|example|demo|localhost|invalid/.test(context)) return "Test / example";
    if (/development|\.env\.dev|dev[_-]|staging|local/.test(context)) return "Development";
    return "Unknown";
  }

  private inferExposure(sourceName: string, nearby: string) {
    const context = `${sourceName}\n${nearby}`.toLowerCase();
    if (/\.github\/workflows|gitlab-ci|circleci|jenkins|pipeline/.test(context)) return "CI/CD workflow";
    if (/(^|\/)\.env|\.env\.|environment/.test(context)) return "Environment configuration";
    if (/docker|kubernetes|k8s|helm|terraform|\.tf\b/.test(context)) return "Infrastructure configuration";
    if (/\.log$|logs?\//.test(sourceName.toLowerCase())) return "Application log";
    if (/\.ya?ml$|\.json$|\.toml$|\.properties$/.test(sourceName.toLowerCase())) return "Configuration file";
    if (sourceName === "Pasted text") return "Pasted text";
    return "Source code";
  }

  private assessRisk({ detector, confidence, environment, exposure, variableName, secret, nearby }: {
    detector: DetectorPattern;
    confidence: Confidence;
    environment: ScanResult["environment"];
    exposure: string;
    variableName?: string;
    secret: string;
    nearby: string;
  }) {
    let score = confidence === "high" ? 72 : confidence === "medium" ? 52 : 30;
    const reasons: string[] = [];
    const descriptor = `${detector.category} ${detector.tokenType} ${detector.serviceType}`.toLowerCase();

    if (/private key|secret access|password|database|personal access|bearer/.test(descriptor)) {
      score += 12;
      reasons.push("This credential type can grant direct access to a protected service.");
    }
    if (environment === "Production") {
      score += 12;
      reasons.push("Nearby text suggests this may belong to a production environment.");
    } else if (environment === "Test / example") {
      score -= 18;
      reasons.push("Nearby text suggests a test, example, or placeholder value.");
    }
    if (/CI\/CD|Infrastructure|Environment/.test(exposure)) {
      score += 7;
      reasons.push(`The value appears inside ${exposure.toLowerCase()}, where secrets are commonly operational.`);
    }
    if (variableName) {
      score += 4;
      reasons.push(`It is assigned to “${variableName}”, which provides stronger contextual evidence.`);
    }

    const compact = secret.replace(/[^A-Za-z0-9]/g, "");
    const distinctCharacters = new Set(compact.toLowerCase()).size;
    if (distinctCharacters <= 4 || /(?:demo|sample|example|placeholder|changeme)/i.test(`${secret} ${nearby}`)) {
      score -= 22;
      reasons.push("The value has placeholder-like characteristics, so manual review is recommended.");
    }

    score = clamp(Math.round(score), 5, 100);
    const risk: RiskLevel = score >= 85 ? "critical" : score >= 65 ? "high" : score >= 40 ? "medium" : "low";
    if (reasons.length === 0) reasons.push("Risk is based on detector specificity and the structure of the matched value.");
    return { score, risk, reasons };
  }

  private deduplicateResults(candidates: DetectionCandidate[]): ScanResult[] {
    const groups = new Map<string, DetectionCandidate[]>();
    for (const candidate of candidates) {
      const key = `${candidate.position}:${candidate.secret}`;
      const group = groups.get(key) ?? [];
      group.push(candidate);
      groups.set(key, group);
    }

    return Array.from(groups.values()).map(group => {
      group.sort((a, b) => b.detectorPriority - a.detectorPriority || b.patternLength - a.patternLength || b.riskScore - a.riskScore);
      const { patternLength: _patternLength, detectorPriority: _detectorPriority, ...result } = group[0];
      return result;
    });
  }

  private isGenericPattern(pattern: string) {
    const genericPatterns = [
      /^\(\[a-zA-Z-0-9\]\{\d+,\d+\}\)$/,
      /^\\b\[a-z0-9\]\{\d+\}\\b$/,
      /^\[a-zA-Z0-9\]\{\d+,\d+\}$/,
      /^\(\?i\)\[a-z0-9\]\{\d+\}$/,
    ];
    return pattern.length < 10 || genericPatterns.some(generic => generic.test(pattern));
  }

  private hasDetectorContext(input: string, detector: DetectorPattern) {
    const haystack = input.toLowerCase();
    const keywords = [detector.name, detector.serviceType, detector.tokenType]
      .flatMap(value => value.toLowerCase().split(/[^a-z0-9]+/))
      .filter(value => value.length >= 4 && !["token", "secret", "access", "generic", "service"].includes(value));
    return keywords.some(keyword => haystack.includes(keyword));
  }

  private getDetectorPriority(detector: DetectorPattern) {
    const name = detector.name.toLowerCase();
    if (/google|amazon|aws|github|stripe|slack|openai|anthropic|azure|twilio|sendgrid|mailgun|datadog|pagerduty/.test(name)) return 100;
    if (/mapbox|planetscale|heroku|digitalocean|mongo|redis|postgres|mysql/.test(name)) return 50;
    if (/generic/.test(name)) return 1;
    return 10;
  }

  private calculateConfidence(secret: string, detector: DetectorPattern): Confidence {
    const entropy = this.calculateEntropy(secret);
    if (detector.defaultConfidence === "high" && secret.length >= 16 && entropy > 2.5) return "high";
    if (detector.defaultConfidence !== "low" && secret.length >= 12 && entropy > 2) return "medium";
    return "low";
  }

  private calculateEntropy(value: string) {
    if (!value.length) return 0;
    const frequencies = new Map<string, number>();
    for (const character of value) frequencies.set(character, (frequencies.get(character) ?? 0) + 1);
    let entropy = 0;
    for (const count of frequencies.values()) {
      const probability = count / value.length;
      entropy -= probability * Math.log2(probability);
    }
    return entropy;
  }

  getDetectorCount() {
    return this.detectors.length;
  }

  getDetectors() {
    return this.detectors;
  }

  auditDetectors(): DetectorAudit {
    const invalidPatterns: DetectorAudit["invalidPatterns"] = [];
    const detectorsWithoutPatterns = this.detectors.filter(detector => detector.patterns.length === 0).map(detector => detector.name);
    let patternCount = 0;

    for (const detector of this.detectors) {
      for (const pattern of detector.patterns) {
        patternCount += 1;
        try {
          const flags = [...new Set(`${pattern.flags}g`)].join("");
          new RegExp(pattern.source, flags);
        } catch (error) {
          invalidPatterns.push({ detector: detector.name, pattern: pattern.source, error: error instanceof Error ? error.message : String(error) });
        }
      }
    }

    return { detectorCount: this.detectors.length, patternCount, invalidPatterns, detectorsWithoutPatterns };
  }
}

export const scanner = new SecretScanner();
