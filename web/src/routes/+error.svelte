<script lang="ts">
  import { page } from "$app/state";
  import { style } from "stillwind/svelte";
</script>

<svelte:head>
  <title>{page.status} · Countersign</title>
</svelte:head>

<div {...style("flex min-h-[55vh] py-10 items-center justify-center")}>
  <div {...style("w-full max-w-md p-6 text-center bg-surface rounded-panel border border-border")}>
    <div
      {...style(
        "flex mx-auto mb-4 size-11 items-center justify-center text-bad bg-bad-soft rounded-full",
      )}
    >
      <span aria-hidden="true" {...style("icon-lg icon-lucide--triangle-alert")}></span>
    </div>
    <p {...style("font-mono text-muted text-xs font-semibold tracking-wider uppercase")}>
      Error {page.status}
    </p>
    <h1 {...style("mt-1 text-foreground text-lg font-semibold")}>
      {page.error?.message || "Something went wrong"}
    </h1>
    <div {...style("mt-5")}>
      <a
        href="/"
        {...style(
          "inline-flex h-9 px-3 items-center gap-1.5 text-foreground text-sm font-medium bg-surface rounded-control border border-border transition-colors hover:bg-surface-hover",
        )}
      >
        <span aria-hidden="true" {...style("icon-sm icon-lucide--chevron-left")}></span>
        Back to requests
      </a>
    </div>
  </div>
</div>
