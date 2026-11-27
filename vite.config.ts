import { defineConfig } from "vite-plus";

// Formatting, linting and tasks for the whole workspace; packages keep
// their own build configuration and tasks.
export default defineConfig({
  fmt: {
    svelte: true,
    sortImports: true,
    sortPackageJson: true,
  },
  lint: {
    rules: {
      curly: "error",
    },
  },
  run: {
    tasks: {
      // The web UI (web/), which countersignd embeds from web/build.
      build: "vp run countersign-web#build",
      check: ["vp check", "vp run countersign-web#check"],
      // The pages with HMR, against the demo daemon (web_demo --dev).
      dev: {
        command: "vp run countersign-web#dev",
        cache: false,
      },
    },
  },
});
