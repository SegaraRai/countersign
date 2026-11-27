<script lang="ts">
  import { page } from "$app/state";
  import { style } from "stillwind/svelte";

  import type { LayoutProps } from "./$types";

  let { data, children }: LayoutProps = $props();

  type NavKey = "requests" | "link" | "admin";

  const links = $derived(
    [
      { href: "/", label: "Requests", key: "requests" as NavKey, show: true },
      { href: "/link", label: "Chat account", key: "link" as NavKey, show: true },
      { href: "/admin", label: "People", key: "admin" as NavKey, show: data.me?.oversees ?? false },
    ].filter((l) => l.show),
  );

  function current(href: string): boolean {
    const path = page.url.pathname;
    return href === "/" ? path === "/" || path.startsWith("/requests/") : path.startsWith(href);
  }

  const initial = $derived((data.me?.name[0] ?? "?").toUpperCase());

  const navIcon = style("icon-sm shrink-0", {
    "data-[icon=requests]:": "icon-lucide--inbox",
    "data-[icon=link]:": "icon-lucide--message-square",
    "data-[icon=admin]:": "icon-lucide--users",
  });
</script>

<div {...style("flex min-h-dvh flex-col bg-background")}>
  <header {...style("sticky top-0 z-20 bg-surface/90 border-border border-b backdrop-blur")}>
    <div {...style("flex mx-auto h-14 max-w-5xl px-4 items-center justify-between gap-4 sm:px-6")}>
      <div {...style("flex min-w-0 items-center gap-6")}>
        <a href="/" aria-label="countersign" {...style("flex shrink-0 items-center")}>
          <img src="/logo.svg" alt="" width="124" height="36" {...style("h-7 w-auto")} />
        </a>
        {#if data.me}
          <nav aria-label="Primary" {...style("hidden items-center gap-1 sm:flex")}>
            {#each links as link (link.href)}
              <a
                href={link.href}
                aria-current={current(link.href) ? "page" : undefined}
                {...style(
                  "flex h-8 px-2.5 items-center gap-2 text-foreground-secondary text-sm font-medium rounded-control transition-colors",
                  {
                    "hover:": "text-foreground bg-surface-hover",
                    "aria-[current=page]:": "text-foreground bg-surface-hover",
                  },
                )}
              >
                <span aria-hidden="true" data-icon={link.key} {...style(navIcon)}></span>
                {link.label}
              </a>
            {/each}
          </nav>
        {/if}
      </div>

      {#if data.me}
        <div {...style("flex min-w-0 items-center gap-3")}>
          <div {...style("flex min-w-0 items-center gap-2")} title={data.me.person}>
            <span
              aria-hidden="true"
              {...style(
                "flex size-7 shrink-0 items-center justify-center text-action text-xs font-semibold bg-action-soft rounded-full",
              )}
            >
              {initial}
            </span>
            <span
              {...style("hidden truncate max-w-40 text-foreground-secondary text-sm md:inline")}
            >
              {data.me.name}
            </span>
          </div>
          <!-- A plain post: countersignd signs out, not the pages. -->
          <form method="post" action="/logout">
            <input type="hidden" name="csrf" value={data.me.csrf} />
            <button
              type="submit"
              title="Sign out"
              {...style(
                "flex h-8 px-2.5 items-center gap-1.5 text-muted text-sm rounded-control transition-colors cursor-pointer",
                {
                  "hover:": "text-foreground bg-surface-hover",
                  "focus-visible:": "outline-2 outline-action outline-offset-2",
                },
              )}
            >
              <span aria-hidden="true" {...style("icon-sm icon-lucide--log-out")}></span>
              <span {...style("hidden lg:inline")}>Sign out</span>
            </button>
          </form>
        </div>
      {/if}
    </div>

    {#if data.me}
      <nav aria-label="Primary" {...style("flex overflow-x-auto px-3 pb-2 gap-1 sm:hidden")}>
        {#each links as link (link.href)}
          <a
            href={link.href}
            aria-current={current(link.href) ? "page" : undefined}
            {...style(
              "flex h-8 px-3 items-center gap-1.5 text-foreground-secondary text-xs font-medium whitespace-nowrap rounded-control transition-colors",
              {
                "hover:": "text-foreground bg-surface-hover",
                "aria-[current=page]:": "text-foreground bg-surface-hover",
              },
            )}
          >
            <span aria-hidden="true" data-icon={link.key} {...style(navIcon)}></span>
            {link.label}
          </a>
        {/each}
      </nav>
    {/if}
  </header>

  <main {...style("min-w-0 flex-1")}>
    <div {...style("mx-auto max-w-5xl px-4 py-8 sm:px-6")}>
      {@render children()}
    </div>
  </main>
</div>
