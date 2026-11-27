import { stillwind } from "@stillwind/integration/vite";
import { sveltekit } from "@sveltejs/kit/vite";
import fetchletAdapter from "fetchlet/sveltekit";
import { defineConfig } from "vite-plus";

export default defineConfig({
  plugins: [
    stillwind(),
    sveltekit({
      // countersignd runs the server code on QuickJS and embeds the build.
      adapter: fetchletAdapter({
        out: "build",
        backend: "quickjs",
        assets: true,
        requirements: ["crypto"],
      }),
      // SvelteKit adds nonces for its own scripts. Inline styles stay
      // allowed for the few style attributes Svelte and Stillwind write.
      csp: {
        mode: "auto",
        directives: {
          "default-src": ["none"],
          "script-src": ["self"],
          "style-src": ["self", "unsafe-inline"],
          "img-src": ["self", "data:"],
          "font-src": ["self"],
          "connect-src": ["self"],
          "manifest-src": ["self"],
          "base-uri": ["none"],
          "frame-ancestors": ["none"],
        },
      },
    }),
  ],
});
