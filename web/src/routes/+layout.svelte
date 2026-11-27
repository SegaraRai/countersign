<script lang="ts">
  import { page } from "$app/state";
  import { style } from "stillwind/svelte";

  import Logo from "#lib/components/Logo.svelte";
  import ThemeToggle from "#lib/components/ThemeToggle.svelte";

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
  <header {...style("sticky top-0 z-20 bg-surface/85 border-border border-b backdrop-blur-md")}>
    <div {...style("flex mx-auto h-14 max-w-5xl px-4 items-center justify-between gap-4 sm:px-6")}>
      <div {...style("flex min-w-0 items-center gap-6")}>
        <a
          href="/"
          aria-label="Countersign"
          {...style(
            "flex shrink-0 items-center rounded-control focus-visible:outline-2 focus-visible:outline-action focus-visible:outline-offset-2",
          )}
        >
          <Logo />
        </a>
        {#if data.me}
          <nav aria-label="Primary" {...style("hidden items-center gap-1 sm:flex")}>
            {#each links as link (link.href)}
              <a
                href={link.href}
                aria-current={current(link.href) ? "page" : undefined}
                {...style(
                  "flex h-8 px-3 items-center gap-2 text-muted text-sm font-medium rounded-control border border-transparent transition-colors",
                  {
                    "hover:": "text-foreground bg-surface-subtle",
                    "aria-[current=page]:": "text-foreground bg-surface-subtle border-border",
                    "focus-visible:": "outline-2 outline-action outline-offset-2",
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

      <div {...style("flex min-w-0 items-center gap-2")}>
        <ThemeToggle />
        {#if data.me}
          <span aria-hidden="true" {...style("hidden h-4 w-px bg-border sm:block")}></span>
          <div {...style("flex min-w-0 pl-1 items-center gap-2")} title={data.me.person}>
            <span
              aria-hidden="true"
              {...style(
                "flex size-7 shrink-0 items-center justify-center text-action text-xs font-semibold bg-action-soft rounded-full border border-action/25",
              )}
            >
              {initial}
            </span>
            <span
              {...style(
                "hidden truncate max-w-40 text-foreground-secondary text-sm font-medium md:inline",
              )}
            >
              {data.me.name}
            </span>
          </div>
          <span aria-hidden="true" {...style("hidden h-4 w-px bg-border sm:block")}></span>
          <!-- A plain post: countersignd signs out, not the pages. -->
          <form method="post" action="/logout">
            <input type="hidden" name="csrf" value={data.me.csrf} />
            <button
              type="submit"
              title="Sign out"
              {...style(
                "flex h-8 px-2.5 items-center gap-1.5 text-muted text-sm rounded-control transition-colors cursor-pointer",
                {
                  "hover:": "text-foreground bg-surface-subtle",
                  "focus-visible:": "outline-2 outline-action outline-offset-2",
                },
              )}
            >
              <span aria-hidden="true" {...style("icon-sm icon-lucide--log-out")}></span>
              <span {...style("hidden lg:inline")}>Sign out</span>
            </button>
          </form>
        {/if}
      </div>
    </div>

    {#if data.me}
      <nav aria-label="Primary" {...style("flex overflow-x-auto px-3 pb-2 gap-1 sm:hidden")}>
        {#each links as link (link.href)}
          <a
            href={link.href}
            aria-current={current(link.href) ? "page" : undefined}
            {...style(
              "flex h-8 px-3 items-center gap-1.5 text-muted text-xs font-medium whitespace-nowrap rounded-control border border-transparent transition-colors",
              {
                "hover:": "text-foreground bg-surface-subtle",
                "aria-[current=page]:": "text-foreground bg-surface-subtle border-border",
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
