import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// GitHub Pages serves a project repo from https://<user>.github.io/<repo>/,
// so the build must use the repo name as its base path. Override with
// BASE_PATH=/ for local single-folder hosting or a custom domain.
export default defineConfig({
  base: process.env.BASE_PATH || "/cyber-projects-kj/showcase/",
  plugins: [react()],
  build: {
    outDir: "dist",
  },
});
