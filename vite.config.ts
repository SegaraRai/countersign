import { defineConfig } from "vite-plus";

// Formatting and linting for the whole workspace; packages keep their own
// build configuration.
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
});
