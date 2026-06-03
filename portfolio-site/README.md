# SOC Analyst Portfolio Site

An interactive, single-page showcase of the three cybersecurity projects in this
repository — built with **React + Vite** and themed like a SOC console.

🔗 **Live site:** `https://rudraxdevelopment98-cell.github.io/cyber-projects-kj/`
(available once GitHub Pages is enabled — see below).

## Features

- Sidebar to switch between the 3 projects
- Tabs per project: **CV bullets**, **tools**, **deliverables**, **certifications**
- MITRE technique / audit check / threat feed chips
- "View source on GitHub" links into each project folder

## Run locally

```bash
cd portfolio-site
npm install
npm run dev      # http://localhost:5173/cyber-projects-kj/
```

## Build

```bash
npm run build    # outputs static files to dist/
npm run preview  # serve the production build locally
```

## Deployment (GitHub Pages)

Deployment is automated by
[`.github/workflows/deploy-portfolio.yml`](../.github/workflows/deploy-portfolio.yml):
every push to `main` that touches `portfolio-site/` builds the site and publishes
it to GitHub Pages.

**One-time setup:** in the GitHub repo go to **Settings → Pages → Build and
deployment → Source** and select **GitHub Actions**. The next push (or a manual
"Run workflow") will publish the site.

> The Vite `base` is set to `/cyber-projects-kj/` for project-pages hosting. For a
> custom domain or root hosting, build with `BASE_PATH=/ npm run build`.
