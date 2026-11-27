import { type ChildProcess, spawn } from "node:child_process";
import { createInterface } from "node:readline";

import { stillwind } from "@stillwind/integration/vite";
import { sveltekit } from "@sveltejs/kit/vite";
import fetchletAdapter from "fetchlet/sveltekit";
import { defineConfig, type Plugin } from "vite-plus";

/** Where `vp run dev` serves the pages. */
const DEV_ORIGIN = "http://localhost:5173";
/** The demo daemon behind it (`web_demo --dev`). */
const DAEMON = process.env.COUNTERSIGN_DEV_DAEMON_URL || "http://127.0.0.1:2770";
/** What countersignd answers itself rather than the pages. */
const DAEMON_PATHS = ["/login", "/auth/", "/logout", "/api/", "/demo-idp", "/healthz"];

/**
 * Builds and starts the demo daemon with the dev server, and stops it with
 * the dev server. Set `COUNTERSIGN_DEV_DAEMON=external` to run it yourself
 * (`cargo run -p countersignd --example web_demo -- --dev <origin>`).
 */
let daemon: ChildProcess | undefined;
process.on("exit", () => daemon?.kill());

function demoDaemon(): Plugin {
  let build: ChildProcess | undefined;
  let child: ChildProcess | undefined;
  let closed = false;
  const stop = () => {
    closed = true;
    build?.kill();
    child?.kill();
  };
  return {
    name: "countersign-demo-daemon",
    apply: "serve",
    configureServer(server) {
      if (process.env.COUNTERSIGN_DEV_DAEMON === "external") {
        return;
      }
      const root = new URL("..", import.meta.url);
      const log = server.config.logger;
      // Build, then run the binary itself: stopping `cargo run` would leave
      // the daemon running on Windows.
      build = spawn(
        "cargo",
        [
          "build",
          "-p",
          "countersignd",
          "--example",
          "web_demo",
          "--message-format=json-render-diagnostics",
        ],
        { cwd: root, stdio: ["ignore", "pipe", "inherit"] },
      );
      let executable: string | undefined;
      createInterface({ input: build.stdout! }).on("line", (line) => {
        try {
          const msg = JSON.parse(line) as {
            reason?: string;
            executable?: string | null;
            target?: { name?: string };
          };
          if (
            msg.reason === "compiler-artifact" &&
            msg.target?.name === "web_demo" &&
            msg.executable
          ) {
            executable = msg.executable;
          }
        } catch {
          // Not a cargo message.
        }
      });
      build.on("close", (code) => {
        build = undefined;
        if (closed) {
          return;
        }
        if (code !== 0 || !executable) {
          log.error(`countersign demo daemon: cargo build failed (${code})`);
          return;
        }
        child = spawn(executable, ["--dev", DEV_ORIGIN], { cwd: root, stdio: "inherit" });
        daemon = child;
        child.on("exit", (status) => {
          if (status !== null && status !== 0) {
            log.error(`countersign demo daemon exited (${status})`);
          }
        });
      });
      server.httpServer?.on("close", stop);
    },
  };
}

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
          // The one inline handler Svelte writes on images
          // (`this.__e=event`, to replay load events after hydration).
          "script-src": [
            "self",
            "unsafe-hashes",
            "sha256-7dQwUgLau1NFCCGjfn9FsYptB6ZtWxJin6VohGIu20I=",
          ],
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
    demoDaemon(),
  ],
  server: {
    port: Number(new URL(DEV_ORIGIN).port),
    strictPort: true,
    proxy: Object.fromEntries(DAEMON_PATHS.map((path) => [path, { target: DAEMON }])),
  },
  run: {
    tasks: {
      build: "vp build",
      check: ["svelte-kit sync", "svelte-check --tsconfig ./tsconfig.json", "stillwind check"],
      dev: {
        command: "vp dev",
        cache: false,
      },
    },
  },
});
