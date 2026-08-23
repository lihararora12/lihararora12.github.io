/**
 * Secret Detection Engine — 50+ Service Detectors
 * Regex patterns sourced from TruffleHog detectors and industry standards.
 */

export type DetectionResult = {
  serviceType: string;
  serviceName: string;
  tokenType: string;
  confidence: "high" | "medium" | "low";
  matchedValue: string;
  extraData?: Record<string, string>;
};

export type Detector = {
  serviceType: string;
  serviceName: string;
  tokenType: string;
  confidence: "high" | "medium" | "low";
  patterns: RegExp[];
  color: string;
  icon: string;
  description: string;
  category: string;
};

export const DETECTORS: Detector[] = [
  // ═══════════════════════════════════════════════════════════════
  // CLOUD PROVIDERS
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "aws_access_key",
    serviceName: "Amazon Web Services",
    tokenType: "Access Key ID",
    confidence: "high",
    patterns: [/\b((?:ASIA|AKIA|AROA|AIDA)[A-Z0-9]{16})\b/],
    color: "#FF9900", icon: "☁️", description: "AWS IAM Access Key ID",
    category: "Cloud",
  },
  {
    serviceType: "aws_secret_key",
    serviceName: "Amazon Web Services",
    tokenType: "Secret Access Key",
    confidence: "high",
    patterns: [/(?<![A-Za-z0-9/+])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+])/],
    color: "#FF9900", icon: "☁️", description: "AWS IAM Secret Access Key",
    category: "Cloud",
  },
  {
    serviceType: "gcp_service_account",
    serviceName: "Google Cloud Platform",
    tokenType: "Service Account Key",
    confidence: "high",
    patterns: [/"type"\s*:\s*"service_account"/, /-----BEGIN RSA PRIVATE KEY-----/],
    color: "#4285F4", icon: "🔵", description: "GCP Service Account JSON Key",
    category: "Cloud",
  },
  {
    serviceType: "google_api_key",
    serviceName: "Google",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bAIza[A-Za-z0-9_-]{35}\b/],
    color: "#4285F4", icon: "🔵", description: "Google API Key",
    category: "Cloud",
  },
  {
    serviceType: "azure_storage_key",
    serviceName: "Microsoft Azure",
    tokenType: "Storage Account Key",
    confidence: "high",
    patterns: [/DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=([A-Za-z0-9+/=]{88});/],
    color: "#0078D4", icon: "☁️", description: "Azure Storage Connection String",
    category: "Cloud",
  },
  {
    serviceType: "azure_client_secret",
    serviceName: "Microsoft Azure",
    tokenType: "Client Secret",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9~._-]{34,40}\b(?=.*azure)/i],
    color: "#0078D4", icon: "☁️", description: "Azure AD Client Secret",
    category: "Cloud",
  },
  {
    serviceType: "digitalocean_pat",
    serviceName: "DigitalOcean",
    tokenType: "Personal Access Token",
    confidence: "high",
    patterns: [/\bdop_v1_[a-f0-9]{64}\b/],
    color: "#0080FF", icon: "🌊", description: "DigitalOcean Personal Access Token",
    category: "Cloud",
  },
  {
    serviceType: "cloudflare_api_key",
    serviceName: "Cloudflare",
    tokenType: "API Key / Token",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9_-]{37}(?:AA[A-Za-z0-9_-]{5})?\b(?=.*cloudflare)/i, /\b[0-9a-f]{37}\b(?=.*cloudflare)/i],
    color: "#F6821F", icon: "🟠", description: "Cloudflare API Key or Token",
    category: "Cloud",
  },
  {
    serviceType: "cloudflare_global_api_key",
    serviceName: "Cloudflare",
    tokenType: "Global API Key",
    confidence: "high",
    patterns: [/\b[0-9a-f]{37}\b/],
    color: "#F6821F", icon: "🟠", description: "Cloudflare Global API Key (37-char hex)",
    category: "Cloud",
  },
  {
    serviceType: "heroku_api_key",
    serviceName: "Heroku",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/],
    color: "#430098", icon: "🟣", description: "Heroku API Key (UUID format)",
    category: "Cloud",
  },
  {
    serviceType: "vercel_token",
    serviceName: "Vercel",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{24}\b(?=.*vercel)/i, /\bvercel_[A-Za-z0-9_-]{24,}\b/i],
    color: "#000000", icon: "▲", description: "Vercel Access Token",
    category: "Cloud",
  },
  {
    serviceType: "netlify_token",
    serviceName: "Netlify",
    tokenType: "Personal Access Token",
    confidence: "high",
    patterns: [/\b[0-9a-f]{40}\b(?=.*netlify)/i],
    color: "#00C7B7", icon: "🟢", description: "Netlify Personal Access Token",
    category: "Cloud",
  },
  {
    serviceType: "terraform_cloud_token",
    serviceName: "Terraform Cloud",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,}\b/],
    color: "#7B42BC", icon: "🔷", description: "Terraform Cloud API Token",
    category: "Cloud",
  },
  {
    serviceType: "pulumi_token",
    serviceName: "Pulumi",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\bpul-[a-f0-9]{40}\b/],
    color: "#8A3391", icon: "🔮", description: "Pulumi Access Token",
    category: "Cloud",
  },

  // ═══════════════════════════════════════════════════════════════
  // SOURCE CONTROL & DEV TOOLS
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "github_pat",
    serviceName: "GitHub",
    tokenType: "Personal Access Token (Classic)",
    confidence: "high",
    patterns: [/\bghp_[A-Za-z0-9]{36,255}\b/],
    color: "#6e40c9", icon: "🐙", description: "GitHub Personal Access Token (classic)",
    category: "DevTools",
  },
  {
    serviceType: "github_pat_fine",
    serviceName: "GitHub",
    tokenType: "Fine-Grained Personal Access Token",
    confidence: "high",
    patterns: [/\bgithub_pat_[A-Za-z0-9_]{82,255}\b/],
    color: "#6e40c9", icon: "🐙", description: "GitHub Fine-Grained PAT",
    category: "DevTools",
  },
  {
    serviceType: "github_oauth",
    serviceName: "GitHub",
    tokenType: "OAuth Token",
    confidence: "high",
    patterns: [/\bgho_[A-Za-z0-9]{36,255}\b/],
    color: "#6e40c9", icon: "🐙", description: "GitHub OAuth Access Token",
    category: "DevTools",
  },
  {
    serviceType: "github_app_token",
    serviceName: "GitHub",
    tokenType: "App Installation Token",
    confidence: "high",
    patterns: [/\bghs_[A-Za-z0-9]{36,255}\b/],
    color: "#6e40c9", icon: "🐙", description: "GitHub App Installation Token",
    category: "DevTools",
  },
  {
    serviceType: "gitlab_pat",
    serviceName: "GitLab",
    tokenType: "Personal Access Token",
    confidence: "high",
    patterns: [/\bglpat-[A-Za-z0-9_-]{20}\b/, /\bglpat-[A-Za-z0-9_-]{20,}\b/],
    color: "#FC6D26", icon: "🦊", description: "GitLab Personal Access Token",
    category: "DevTools",
  },
  {
    serviceType: "gitlab_runner_token",
    serviceName: "GitLab",
    tokenType: "Runner Registration Token",
    confidence: "high",
    patterns: [/\bglrt-[A-Za-z0-9_-]{20,}\b/, /\bGR1348941[A-Za-z0-9_-]{20}\b/],
    color: "#FC6D26", icon: "🦊", description: "GitLab Runner Token",
    category: "DevTools",
  },
  {
    serviceType: "bitbucket_client_secret",
    serviceName: "Bitbucket",
    tokenType: "OAuth Client Secret",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9]{32}\b(?=.*bitbucket)/i],
    color: "#0052CC", icon: "🪣", description: "Bitbucket OAuth Client Secret",
    category: "DevTools",
  },
  {
    serviceType: "npm_token",
    serviceName: "npm",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\bnpm_[A-Za-z0-9]{36}\b/],
    color: "#CB3837", icon: "📦", description: "npm Access Token",
    category: "DevTools",
  },
  {
    serviceType: "pypi_token",
    serviceName: "PyPI",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\bpypi-[A-Za-z0-9_-]{80,}\b/],
    color: "#3775A9", icon: "🐍", description: "PyPI API Token",
    category: "DevTools",
  },
  {
    serviceType: "rubygems_token",
    serviceName: "RubyGems",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\brubygems_[a-f0-9]{48}\b/],
    color: "#E9573F", icon: "💎", description: "RubyGems API Key",
    category: "DevTools",
  },
  {
    serviceType: "docker_hub_token",
    serviceName: "Docker Hub",
    tokenType: "Personal Access Token",
    confidence: "high",
    patterns: [/\bdckr_pat_[A-Za-z0-9_-]{27}\b/],
    color: "#2496ED", icon: "🐳", description: "Docker Hub Personal Access Token",
    category: "DevTools",
  },
  {
    serviceType: "sentry_dsn",
    serviceName: "Sentry",
    tokenType: "DSN / Auth Token",
    confidence: "high",
    patterns: [/https?:\/\/[a-f0-9]{32}@(?:o\d+\.)?sentry\.io\/\d+/, /\bsntrys_[A-Za-z0-9]{64}\b/],
    color: "#362D59", icon: "🔍", description: "Sentry DSN or Auth Token",
    category: "DevTools",
  },
  {
    serviceType: "snyk_token",
    serviceName: "Snyk",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*snyk)/i],
    color: "#4C4A73", icon: "🛡️", description: "Snyk API Token",
    category: "DevTools",
  },
  {
    serviceType: "linear_api_key",
    serviceName: "Linear",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\blin_api_[A-Za-z0-9]{40}\b/],
    color: "#5E6AD2", icon: "📐", description: "Linear API Key",
    category: "DevTools",
  },
  {
    serviceType: "jira_api_token",
    serviceName: "Jira / Atlassian",
    tokenType: "API Token",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9]{24}\b(?=.*atlassian|.*jira)/i, /ATATT[A-Za-z0-9_-]{100,}/],
    color: "#0052CC", icon: "🔵", description: "Jira / Atlassian API Token",
    category: "DevTools",
  },

  // ═══════════════════════════════════════════════════════════════
  // COMMUNICATION & COLLABORATION
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "slack_bot_token",
    serviceName: "Slack",
    tokenType: "Bot Token",
    confidence: "high",
    patterns: [/\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}\b/],
    color: "#4A154B", icon: "💬", description: "Slack Bot OAuth Token",
    category: "Communication",
  },
  {
    serviceType: "slack_user_token",
    serviceName: "Slack",
    tokenType: "User Token",
    confidence: "high",
    patterns: [/\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32,64}\b/],
    color: "#4A154B", icon: "💬", description: "Slack User OAuth Token",
    category: "Communication",
  },
  {
    serviceType: "slack_workspace_token",
    serviceName: "Slack",
    tokenType: "Workspace Access Token",
    confidence: "high",
    patterns: [/\bxoxa-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{32,64}\b/],
    color: "#4A154B", icon: "💬", description: "Slack Workspace Access Token",
    category: "Communication",
  },
  {
    serviceType: "slack_webhook",
    serviceName: "Slack",
    tokenType: "Incoming Webhook",
    confidence: "high",
    patterns: [/https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,10}\/B[A-Z0-9]{8,10}\/[A-Za-z0-9]{24,32}/],
    color: "#4A154B", icon: "💬", description: "Slack Incoming Webhook URL",
    category: "Communication",
  },
  {
    serviceType: "discord_bot_token",
    serviceName: "Discord",
    tokenType: "Bot Token",
    confidence: "high",
    patterns: [/\b[MNO][A-Za-z0-9]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}\b/],
    color: "#5865F2", icon: "🎮", description: "Discord Bot Token",
    category: "Communication",
  },
  {
    serviceType: "discord_webhook",
    serviceName: "Discord",
    tokenType: "Webhook URL",
    confidence: "high",
    patterns: [/https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,19}\/[A-Za-z0-9_-]{68}/],
    color: "#5865F2", icon: "🎮", description: "Discord Webhook URL",
    category: "Communication",
  },
  {
    serviceType: "twilio_account_sid",
    serviceName: "Twilio",
    tokenType: "Account SID",
    confidence: "high",
    patterns: [/\bAC[a-z0-9]{32}\b/],
    color: "#F22F46", icon: "📱", description: "Twilio Account SID",
    category: "Communication",
  },
  {
    serviceType: "twilio_auth_token",
    serviceName: "Twilio",
    tokenType: "Auth Token",
    confidence: "medium",
    patterns: [/(?:twilio)[\s\S]{0,40}\b([a-f0-9]{32})\b/i],
    color: "#F22F46", icon: "📱", description: "Twilio Auth Token",
    category: "Communication",
  },
  {
    serviceType: "sendgrid_api_key",
    serviceName: "SendGrid",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{43,}\b/],
    color: "#1A82E2", icon: "📧", description: "SendGrid API Key",
    category: "Communication",
  },
  {
    serviceType: "mailgun_api_key",
    serviceName: "Mailgun",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bkey-[a-z0-9]{32}\b/, /\bpubkey-[a-z0-9]{32}\b/],
    color: "#F06B66", icon: "📬", description: "Mailgun API Key",
    category: "Communication",
  },
  {
    serviceType: "postmark_server_token",
    serviceName: "Postmark",
    tokenType: "Server API Token",
    confidence: "high",
    patterns: [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*postmark)/i],
    color: "#FFDE00", icon: "📮", description: "Postmark Server API Token",
    category: "Communication",
  },
  {
    serviceType: "zendesk_api_token",
    serviceName: "Zendesk",
    tokenType: "API Token",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9]{40}\b(?=.*zendesk)/i],
    color: "#03363D", icon: "🎫", description: "Zendesk API Token",
    category: "Communication",
  },
  {
    serviceType: "intercom_access_token",
    serviceName: "Intercom",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\bdG9r[A-Za-z0-9_-]{50,}\b/, /\b[A-Za-z0-9_-]{60,}\b(?=.*intercom)/i],
    color: "#1F8DED", icon: "💬", description: "Intercom Access Token",
    category: "Communication",
  },

  // ═══════════════════════════════════════════════════════════════
  // AI / ML SERVICES
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "openai_api_key",
    serviceName: "OpenAI",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/, /\bsk-proj-[A-Za-z0-9_-]{50,200}\b/, /\bsk-[A-Za-z0-9-_]{32,200}\b/],
    color: "#10a37f", icon: "🤖", description: "OpenAI API Key",
    category: "AI/ML",
  },
  {
    serviceType: "anthropic_api_key",
    serviceName: "Anthropic",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bsk-ant-[A-Za-z0-9_-]{95,110}\b/],
    color: "#D4A574", icon: "🧠", description: "Anthropic Claude API Key",
    category: "AI/ML",
  },
  {
    serviceType: "huggingface_token",
    serviceName: "Hugging Face",
    tokenType: "User Access Token",
    confidence: "high",
    patterns: [/\bhf_[A-Za-z0-9]{34,40}\b/],
    color: "#FFD21E", icon: "🤗", description: "Hugging Face User Access Token",
    category: "AI/ML",
  },
  {
    serviceType: "cohere_api_key",
    serviceName: "Cohere",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{40}\b(?=.*cohere)/i, /\bco-[A-Za-z0-9_-]{40,}\b/],
    color: "#39594D", icon: "🌿", description: "Cohere API Key",
    category: "AI/ML",
  },
  {
    serviceType: "replicate_api_token",
    serviceName: "Replicate",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\br8_[A-Za-z0-9]{37}\b/],
    color: "#000000", icon: "🔁", description: "Replicate API Token",
    category: "AI/ML",
  },
  {
    serviceType: "pinecone_api_key",
    serviceName: "Pinecone",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*pinecone)/i],
    color: "#00C4B4", icon: "🌲", description: "Pinecone API Key",
    category: "AI/ML",
  },
  {
    serviceType: "groq_api_key",
    serviceName: "Groq",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bgsk_[A-Za-z0-9]{52}\b/],
    color: "#F55036", icon: "⚡", description: "Groq API Key",
    category: "AI/ML",
  },
  {
    serviceType: "mistral_api_key",
    serviceName: "Mistral AI",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{32}\b(?=.*mistral)/i],
    color: "#FF7000", icon: "🌬️", description: "Mistral AI API Key",
    category: "AI/ML",
  },
  {
    serviceType: "perplexity_api_key",
    serviceName: "Perplexity",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bpplx-[A-Za-z0-9]{48}\b/],
    color: "#20808D", icon: "🔮", description: "Perplexity API Key",
    category: "AI/ML",
  },
  {
    serviceType: "stability_api_key",
    serviceName: "Stability AI",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bsk-[A-Za-z0-9]{48}\b(?=.*stability)/i],
    color: "#7C3AED", icon: "🎨", description: "Stability AI API Key",
    category: "AI/ML",
  },

  // ═══════════════════════════════════════════════════════════════
  // PAYMENTS & FINTECH
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "stripe_secret_key",
    serviceName: "Stripe",
    tokenType: "Secret Key",
    confidence: "high",
    patterns: [/\bsk_(live|test)_[A-Za-z0-9]{24,99}\b/],
    color: "#635BFF", icon: "💳", description: "Stripe Secret API Key",
    category: "Payments",
  },
  {
    serviceType: "stripe_publishable_key",
    serviceName: "Stripe",
    tokenType: "Publishable Key",
    confidence: "high",
    patterns: [/\bpk_(live|test)_[A-Za-z0-9]{24,99}\b/],
    color: "#635BFF", icon: "💳", description: "Stripe Publishable API Key",
    category: "Payments",
  },
  {
    serviceType: "stripe_restricted_key",
    serviceName: "Stripe",
    tokenType: "Restricted Key",
    confidence: "high",
    patterns: [/\brk_(live|test)_[A-Za-z0-9]{24,99}\b/],
    color: "#635BFF", icon: "💳", description: "Stripe Restricted API Key",
    category: "Payments",
  },
  {
    serviceType: "square_access_token",
    serviceName: "Square",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\bEAAAE[A-Za-z0-9_-]{60,}\b/, /\bsandbox-sq0[a-z]{3}-[A-Za-z0-9_-]{40,}\b/],
    color: "#3E4348", icon: "⬛", description: "Square Access Token",
    category: "Payments",
  },
  {
    serviceType: "braintree_access_token",
    serviceName: "Braintree",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b/],
    color: "#009CDE", icon: "💰", description: "Braintree Access Token",
    category: "Payments",
  },
  {
    serviceType: "plaid_client_secret",
    serviceName: "Plaid",
    tokenType: "Client Secret",
    confidence: "high",
    patterns: [/\b[a-f0-9]{30}\b(?=.*plaid)/i],
    color: "#00A3E0", icon: "🏦", description: "Plaid Client Secret",
    category: "Payments",
  },
  {
    serviceType: "coinbase_api_key",
    serviceName: "Coinbase",
    tokenType: "API Key",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9]{16}\b(?=.*coinbase)/i],
    color: "#0052FF", icon: "₿", description: "Coinbase API Key",
    category: "Payments",
  },
  {
    serviceType: "shopify_access_token",
    serviceName: "Shopify",
    tokenType: "Admin API Access Token",
    confidence: "high",
    patterns: [/\bshpat_[a-fA-F0-9]{32}\b/, /\bshpss_[a-fA-F0-9]{32}\b/, /\bshpca_[a-fA-F0-9]{32}\b/],
    color: "#96BF48", icon: "🛍️", description: "Shopify Admin API Access Token",
    category: "Payments",
  },

  // ═══════════════════════════════════════════════════════════════
  // DATABASES & DATA PLATFORMS
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "supabase_service_key",
    serviceName: "Supabase",
    tokenType: "Service Role Key",
    confidence: "high",
    patterns: [/\beyJ[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{100,}\.[A-Za-z0-9_-]{43}\b/],
    color: "#3ECF8E", icon: "🟢", description: "Supabase JWT Service Role Key",
    category: "Database",
  },
  {
    serviceType: "firebase_api_key",
    serviceName: "Firebase",
    tokenType: "Web API Key",
    confidence: "high",
    patterns: [/\bAIza[A-Za-z0-9_-]{35}\b(?=.*firebase)/i],
    color: "#FFCA28", icon: "🔥", description: "Firebase Web API Key",
    category: "Database",
  },
  {
    serviceType: "mongodb_atlas_uri",
    serviceName: "MongoDB Atlas",
    tokenType: "Connection URI",
    confidence: "high",
    patterns: [/mongodb(?:\+srv)?:\/\/[^:]+:[^@]+@[a-z0-9.-]+\.mongodb\.net/i],
    color: "#00ED64", icon: "🍃", description: "MongoDB Atlas Connection URI",
    category: "Database",
  },
  {
    serviceType: "elastic_cloud_api_key",
    serviceName: "Elastic Cloud",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9_-]{32,}==[A-Za-z0-9_-]{32,}==\b/, /\bApiKey [A-Za-z0-9+/=]{60,}\b/],
    color: "#FEC514", icon: "🔍", description: "Elastic Cloud API Key",
    category: "Database",
  },
  {
    serviceType: "snowflake_credentials",
    serviceName: "Snowflake",
    tokenType: "Account Credentials",
    confidence: "medium",
    patterns: [/[a-z0-9-]+\.snowflakecomputing\.com/i],
    color: "#29B5E8", icon: "❄️", description: "Snowflake Account Identifier",
    category: "Database",
  },
  {
    serviceType: "databricks_token",
    serviceName: "Databricks",
    tokenType: "Personal Access Token",
    confidence: "high",
    patterns: [/\bdapi[a-f0-9]{32}\b/],
    color: "#FF3621", icon: "🧱", description: "Databricks Personal Access Token",
    category: "Database",
  },
  {
    serviceType: "airtable_api_key",
    serviceName: "Airtable",
    tokenType: "API Key / Token",
    confidence: "high",
    patterns: [/\bkey[A-Za-z0-9]{14}\b/, /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/],
    color: "#FCB400", icon: "📊", description: "Airtable API Key or Personal Access Token",
    category: "Database",
  },
  {
    serviceType: "notion_integration_token",
    serviceName: "Notion",
    tokenType: "Integration Token",
    confidence: "high",
    patterns: [/\bsecret_[A-Za-z0-9]{43}\b/, /\bntn_[A-Za-z0-9]{43}\b/],
    color: "#000000", icon: "📝", description: "Notion Integration Token",
    category: "Database",
  },

  // ═══════════════════════════════════════════════════════════════
  // MONITORING & OBSERVABILITY
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "datadog_api_key",
    serviceName: "Datadog",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[a-f0-9]{32}\b(?=.*datadog|.*DD_API_KEY)/i, /\bddapikey[_-]?[a-f0-9]{32}\b/i],
    color: "#632CA6", icon: "🐶", description: "Datadog API Key",
    category: "Monitoring",
  },
  {
    serviceType: "datadog_app_key",
    serviceName: "Datadog",
    tokenType: "Application Key",
    confidence: "high",
    patterns: [/\b[a-f0-9]{40}\b(?=.*datadog|.*DD_APP_KEY)/i],
    color: "#632CA6", icon: "🐶", description: "Datadog Application Key",
    category: "Monitoring",
  },
  {
    serviceType: "pagerduty_api_key",
    serviceName: "PagerDuty",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9_-]{20}\b(?=.*pagerduty)/i, /\bu\+[A-Za-z0-9_-]{20}\b/],
    color: "#06AC38", icon: "🚨", description: "PagerDuty API Key",
    category: "Monitoring",
  },
  {
    serviceType: "new_relic_api_key",
    serviceName: "New Relic",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bNRAK-[A-Z0-9]{32}\b/, /\bNRII-[A-Z0-9]{32}\b/, /\bNRSR-[A-Z0-9]{32}\b/],
    color: "#008C99", icon: "📈", description: "New Relic API Key",
    category: "Monitoring",
  },
  {
    serviceType: "grafana_api_key",
    serviceName: "Grafana",
    tokenType: "API Key / Service Account Token",
    confidence: "high",
    patterns: [/\bglsa_[A-Za-z0-9_-]{32}_[A-Za-z0-9]{8}\b/, /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b(?=.*grafana)/i],
    color: "#F46800", icon: "📊", description: "Grafana API Key or Service Account Token",
    category: "Monitoring",
  },

  // ═══════════════════════════════════════════════════════════════
  // IDENTITY & ACCESS MANAGEMENT
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "okta_api_token",
    serviceName: "Okta",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\b00[A-Za-z0-9_-]{40}\b/],
    color: "#007DC1", icon: "🔐", description: "Okta API Token",
    category: "IAM",
  },
  {
    serviceType: "vault_token",
    serviceName: "HashiCorp Vault",
    tokenType: "Service Token",
    confidence: "high",
    patterns: [/\bhvs\.[A-Za-z0-9_-]{90,}\b/, /\bs\.[A-Za-z0-9]{24}\b/],
    color: "#000000", icon: "🏛️", description: "HashiCorp Vault Service Token",
    category: "IAM",
  },
  {
    serviceType: "auth0_client_secret",
    serviceName: "Auth0",
    tokenType: "Client Secret",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9_-]{64}\b(?=.*auth0)/i],
    color: "#EB5424", icon: "🔒", description: "Auth0 Client Secret",
    category: "IAM",
  },

  // ═══════════════════════════════════════════════════════════════
  // SOCIAL & MEDIA PLATFORMS
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "twitter_bearer_token",
    serviceName: "Twitter / X",
    tokenType: "Bearer Token",
    confidence: "high",
    patterns: [/\bAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]{80,}\b/],
    color: "#1DA1F2", icon: "🐦", description: "Twitter/X Bearer Token",
    category: "Social",
  },
  {
    serviceType: "twitter_api_key",
    serviceName: "Twitter / X",
    tokenType: "API Key / Secret",
    confidence: "medium",
    patterns: [/\b[A-Za-z0-9]{25}\b(?=.*twitter|.*TWITTER_API)/i],
    color: "#1DA1F2", icon: "🐦", description: "Twitter/X API Key",
    category: "Social",
  },
  {
    serviceType: "twitch_client_secret",
    serviceName: "Twitch",
    tokenType: "Client Secret",
    confidence: "high",
    patterns: [/\b[a-z0-9]{30}\b(?=.*twitch)/i],
    color: "#9146FF", icon: "🎮", description: "Twitch Client Secret",
    category: "Social",
  },
  {
    serviceType: "spotify_client_secret",
    serviceName: "Spotify",
    tokenType: "Client Secret",
    confidence: "high",
    patterns: [/\b[a-f0-9]{32}\b(?=.*spotify)/i],
    color: "#1DB954", icon: "🎵", description: "Spotify Client Secret",
    category: "Social",
  },
  {
    serviceType: "youtube_api_key",
    serviceName: "YouTube",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bAIza[A-Za-z0-9_-]{35}\b(?=.*youtube)/i],
    color: "#FF0000", icon: "▶️", description: "YouTube Data API Key",
    category: "Social",
  },

  // ═══════════════════════════════════════════════════════════════
  // SEARCH & DATA
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "algolia_api_key",
    serviceName: "Algolia",
    tokenType: "Admin API Key",
    confidence: "high",
    patterns: [/\b[a-f0-9]{32}\b(?=.*algolia|.*ALGOLIA)/i],
    color: "#003DFF", icon: "🔎", description: "Algolia Admin API Key",
    category: "Search",
  },
  {
    serviceType: "mapbox_token",
    serviceName: "Mapbox",
    tokenType: "Access Token",
    confidence: "high",
    patterns: [/\bpk\.eyJ1[A-Za-z0-9._-]{60,}\b/, /\bsk\.eyJ1[A-Za-z0-9._-]{60,}\b/],
    color: "#4264FB", icon: "🗺️", description: "Mapbox Access Token",
    category: "Search",
  },

  // ═══════════════════════════════════════════════════════════════
  // CRM & MARKETING
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "salesforce_token",
    serviceName: "Salesforce",
    tokenType: "Access Token / Connected App Secret",
    confidence: "medium",
    patterns: [/\b00D[A-Za-z0-9]{15}![A-Za-z0-9._-]{90,}\b/],
    color: "#00A1E0", icon: "☁️", description: "Salesforce Access Token",
    category: "CRM",
  },
  {
    serviceType: "hubspot_api_key",
    serviceName: "HubSpot",
    tokenType: "API Key / Private App Token",
    confidence: "high",
    patterns: [/\bpat-[a-z]{2}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/],
    color: "#FF7A59", icon: "🧡", description: "HubSpot Private App Token",
    category: "CRM",
  },

  // ═══════════════════════════════════════════════════════════════
  // STORAGE
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "dropbox_api_key",
    serviceName: "Dropbox",
    tokenType: "API Key / Access Token",
    confidence: "high",
    patterns: [/\bsl\.[A-Za-z0-9_-]{130,160}\b/],
    color: "#0061FF", icon: "📦", description: "Dropbox API Access Token",
    category: "Storage",
  },
  {
    serviceType: "cloudinary_url",
    serviceName: "Cloudinary",
    tokenType: "API URL / Secret",
    confidence: "high",
    patterns: [/cloudinary:\/\/[A-Za-z0-9_-]+:[A-Za-z0-9_-]+@[a-z0-9_-]+/i, /\bCLOUDINARY_URL\s*=\s*cloudinary:\/\//i],
    color: "#3448C5", icon: "🖼️", description: "Cloudinary API URL with credentials",
    category: "Storage",
  },
  {
    serviceType: "aws_s3_presigned",
    serviceName: "AWS S3",
    tokenType: "Pre-signed URL",
    confidence: "medium",
    patterns: [/https:\/\/[a-z0-9.-]+\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/[^?]+\?X-Amz-Signature=[a-f0-9]+/i],
    color: "#FF9900", icon: "🪣", description: "AWS S3 Pre-signed URL",
    category: "Storage",
  },

  // ═══════════════════════════════════════════════════════════════
  // INFRASTRUCTURE & HOSTING
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "fly_io_token",
    serviceName: "Fly.io",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\bFlyV1 [A-Za-z0-9+/=]{100,}\b/, /\bfo1_[A-Za-z0-9_-]{40,}\b/],
    color: "#7B2FBE", icon: "✈️", description: "Fly.io API Token",
    category: "Cloud",
  },
  {
    serviceType: "render_api_key",
    serviceName: "Render",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\brnd_[A-Za-z0-9]{32,}\b/],
    color: "#46E3B7", icon: "🟩", description: "Render API Key",
    category: "Cloud",
  },
  {
    serviceType: "railway_token",
    serviceName: "Railway",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b(?=.*railway)/i],
    color: "#0B0D0E", icon: "🚂", description: "Railway API Token",
    category: "Cloud",
  },
  {
    serviceType: "fastly_api_key",
    serviceName: "Fastly",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9_-]{32}\b(?=.*fastly)/i],
    color: "#FF282D", icon: "⚡", description: "Fastly API Key",
    category: "Cloud",
  },
  {
    serviceType: "linode_token",
    serviceName: "Linode / Akamai Cloud",
    tokenType: "Personal Access Token",
    confidence: "high",
    patterns: [/\b[a-f0-9]{64}\b(?=.*linode)/i],
    color: "#02B159", icon: "🌐", description: "Linode Personal Access Token",
    category: "Cloud",
  },
  {
    serviceType: "vultr_api_key",
    serviceName: "Vultr",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Z0-9]{36}\b(?=.*vultr)/i],
    color: "#007BFC", icon: "🔵", description: "Vultr API Key",
    category: "Cloud",
  },

  // ═══════════════════════════════════════════════════════════════
  // EMAIL & COMMUNICATION
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "resend_api_key",
    serviceName: "Resend",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bre_[A-Za-z0-9_-]{32,}\b/],
    color: "#000000", icon: "📨", description: "Resend API Key",
    category: "Communication",
  },
  {
    serviceType: "loops_api_key",
    serviceName: "Loops",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{32}\b(?=.*loops)/i],
    color: "#6C47FF", icon: "🔄", description: "Loops API Key",
    category: "Communication",
  },
  {
    serviceType: "vonage_api_key",
    serviceName: "Vonage / Nexmo",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[a-f0-9]{8}\b(?=.*vonage|.*nexmo)/i],
    color: "#131415", icon: "📞", description: "Vonage/Nexmo API Key",
    category: "Communication",
  },
  {
    serviceType: "messagebird_api_key",
    serviceName: "MessageBird",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{25}\b(?=.*messagebird|.*bird)/i],
    color: "#2481D7", icon: "🐦", description: "MessageBird API Key",
    category: "Communication",
  },
  {
    serviceType: "courier_api_key",
    serviceName: "Courier",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bpk_[A-Za-z0-9]{32,}\b(?=.*courier)/i, /\bdk_[A-Za-z0-9]{32,}\b(?=.*courier)/i],
    color: "#9B5DE5", icon: "📬", description: "Courier API Key",
    category: "Communication",
  },

  // ═══════════════════════════════════════════════════════════════
  // VECTOR DATABASES & AI INFRA (additional)
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "together_ai_key",
    serviceName: "Together AI",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[a-f0-9]{64}\b(?=.*together)/i],
    color: "#0F172A", icon: "🤝", description: "Together AI API Key",
    category: "AI/ML",
  },
  {
    serviceType: "fireworks_api_key",
    serviceName: "Fireworks AI",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\bfw_[A-Za-z0-9]{32,}\b/],
    color: "#FF6B35", icon: "🎆", description: "Fireworks AI API Key",
    category: "AI/ML",
  },

  // ═══════════════════════════════════════════════════════════════
  // PAYMENTS & BILLING
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "paddle_api_key",
    serviceName: "Paddle",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{32}\b(?=.*paddle)/i, /\bpdl_[A-Za-z0-9_-]{40,}\b/],
    color: "#0EA5E9", icon: "🏓", description: "Paddle API Key",
    category: "Payments",
  },
  {
    serviceType: "lemonsqueezy_api_key",
    serviceName: "Lemon Squeezy",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\beyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b(?=.*lemon)/i],
    color: "#FFD700", icon: "🍋", description: "Lemon Squeezy API Key",
    category: "Payments",
  },

  // ═══════════════════════════════════════════════════════════════
  // MEDIA & CONTENT
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "pexels_api_key",
    serviceName: "Pexels",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{56}\b(?=.*pexels)/i],
    color: "#05A081", icon: "📷", description: "Pexels API Key",
    category: "Media",
  },
  {
    serviceType: "unsplash_access_key",
    serviceName: "Unsplash",
    tokenType: "Access Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9_-]{43}\b(?=.*unsplash)/i],
    color: "#111111", icon: "📸", description: "Unsplash Access Key",
    category: "Media",
  },
  {
    serviceType: "giphy_api_key",
    serviceName: "GIPHY",
    tokenType: "API Key",
    confidence: "high",
    patterns: [/\b[A-Za-z0-9]{32}\b(?=.*giphy)/i],
    color: "#FF6666", icon: "🎞️", description: "GIPHY API Key",
    category: "Media",
  },
  {
    serviceType: "cloudflare_stream_key",
    serviceName: "Cloudflare Stream",
    tokenType: "Stream Key",
    confidence: "high",
    patterns: [/\b[a-f0-9]{32}\b(?=.*stream|.*cloudflare)/i],
    color: "#F6821F", icon: "📹", description: "Cloudflare Stream Key",
    category: "Media",
  },

  // ═══════════════════════════════════════════════════════════════
  // SECURITY & CERTIFICATES
  // ═══════════════════════════════════════════════════════════════
  {
    serviceType: "private_key_rsa",
    serviceName: "RSA Private Key",
    tokenType: "Private Key",
    confidence: "high",
    patterns: [/-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/],
    color: "#DC2626", icon: "🔑", description: "PEM-encoded private key",
    category: "Certificates",
  },
  {
    serviceType: "jwt_token",
    serviceName: "JSON Web Token",
    tokenType: "JWT",
    confidence: "medium",
    patterns: [/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/],
    color: "#D63AFF", icon: "🎟️", description: "JSON Web Token (JWT)",
    category: "Certificates",
  },
  {
    serviceType: "generic_api_key",
    serviceName: "Generic API Key",
    tokenType: "API Key (Generic Pattern)",
    confidence: "low",
    patterns: [/(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token|auth[_-]?token)\s*[=:"']\s*([A-Za-z0-9_/+.-]{20,})/i],
    color: "#6B7280", icon: "🔐", description: "Generic API key pattern from variable assignment",
    category: "Generic",
  },
  {
    serviceType: "generic_secret",
    serviceName: "Generic Secret",
    tokenType: "Secret (Generic Pattern)",
    confidence: "low",
    patterns: [/(?:secret|password|passwd|pwd|token|credential)\s*[=:"']\s*([A-Za-z0-9!@#$%^&*_/+.-]{16,})/i],
    color: "#6B7280", icon: "🔒", description: "Generic secret pattern from variable assignment",
    category: "Generic",
  },
  // ─── Data Science ─────────────────────────────────────────────────────────────
  {
    serviceType: "kaggle_api_token",
    serviceName: "Kaggle",
    tokenType: "API Token",
    confidence: "high",
    patterns: [/\bKGAT_[a-f0-9]{32}\b/],
    color: "#20BEFF",
    icon: "📊",
    description: "Kaggle API Token (KGAT_*)",
    category: "Data Science",
  },
];

/**
 * Detect all matching token types in a given string.
 */
export function detectTokens(input: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const seen = new Set<string>();

  for (const detector of DETECTORS) {
    for (const pattern of detector.patterns) {
      const match = pattern.exec(input);
      if (match) {
        const matchedValue = match[1] ?? match[0];
        const key = `${detector.serviceType}:${matchedValue}`;
        if (!seen.has(key)) {
          seen.add(key);
          results.push({
            serviceType: detector.serviceType,
            serviceName: detector.serviceName,
            tokenType: detector.tokenType,
            confidence: detector.confidence,
            matchedValue,
          });
        }
      }
    }
  }

  return results;
}

/**
 * Get detector metadata by serviceType.
 */
export function getDetector(serviceType: string): Detector | undefined {
  return DETECTORS.find((d) => d.serviceType === serviceType);
}

/**
 * Mask a token for safe display (show first 8 and last 4 chars).
 */
export function maskToken(token: string): string {
  if (token.length <= 12) return "****";
  const prefix = token.slice(0, 8);
  const suffix = token.slice(-4);
  return `${prefix}...${suffix}`;
}

/**
 * Get all unique categories.
 */
export function getCategories(): string[] {
  const seen = new Set<string>();
  return DETECTORS.map((d) => d.category).filter((c) => {
    if (seen.has(c)) return false;
    seen.add(c);
    return true;
  });
}

/**
 * Get detectors by category.
 */
export function getDetectorsByCategory(category: string): Detector[] {
  return DETECTORS.filter((d) => d.category === category);
}
