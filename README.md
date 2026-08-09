# vuln.management

An independent static publication about vulnerability management, AI agents, remediation systems, security advisories, and the absurdity encountered along the way.

The site is built with [Astro](https://astro.build/) and deployed to GitHub Pages. It has no server, database, analytics, or runtime content dependency.

## Local development

```sh
npm install
npm run dev
```

Open the local URL printed by Astro. To run type checks and generate the production site:

```sh
npm run build
npm run preview
```

## Publishing content

Posts live in `src/content/posts/`. Advisories live in `src/content/advisories/`. Copy the corresponding file in `templates/`, edit the frontmatter and body, then change `draft` to `false` when it is ready to publish.

Advisories are editorial summaries. Link the vendor bulletin and a canonical CVE or GHSA source, distinguish source facts from interpretation, and never guess affected or fixed versions. Each advisory includes a concise ELI5 explanation, a three-to-five-step visual attack flow, and controlled taxonomy fields for technology, weakness, impact, evidence, and action. Those fields power the static Advisory Explorer and its shareable URL filters. The vendor remains authoritative.

The existing meme images are served from `public/images/photos/`. Additions should follow the current `memes-N.jpg` naming convention and the count in `src/pages/memes/index.astro` should be updated.

## GitHub Pages

Pushes to `master` run `.github/workflows/deploy.yml`. In the repository settings, set **Pages → Build and deployment → Source** to **GitHub Actions**. The custom domain is retained through `public/CNAME`.

## Public-content boundary

This is a public, independent project. Do not add confidential employer information, internal URLs, proprietary code, private incident details, credentials, or non-public vulnerability data.
