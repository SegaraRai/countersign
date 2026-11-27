<script lang="ts">
  import { style } from "stillwind/svelte";

  import type { PageProps } from "./$types";

  let { data }: PageProps = $props();
</script>

<svelte:head>
  <title>{data.notice.heading} · Countersign</title>
</svelte:head>

<div {...style("flex min-h-[55vh] py-10 items-center justify-center")}>
  <div {...style("w-full max-w-md p-6 text-center bg-surface rounded-panel border border-border")}>
    <h1 {...style("text-foreground text-lg font-semibold")}>{data.notice.heading}</h1>
    <p {...style("mt-2 text-foreground-secondary text-sm leading-relaxed")}>{data.notice.body}</p>
    {#if data.notice.detail}
      <code
        {...style(
          "block mt-4 px-3 py-2 font-mono text-foreground text-xs break-all bg-code rounded-control border border-border select-all",
        )}>{data.notice.detail}</code
      >
    {/if}
    <div {...style("flex mt-6 justify-center gap-2")}>
      {#if data.me}
        <a
          href="/"
          {...style(
            "inline-flex h-9 px-3.5 items-center text-foreground text-sm font-medium bg-surface rounded-control border border-border hover:bg-surface-hover",
          )}>Back to requests</a
        >
      {:else}
        <a
          href="/login?next=%2F"
          data-sveltekit-reload
          {...style(
            "inline-flex h-9 px-3.5 items-center text-action-foreground text-sm font-medium bg-action rounded-control hover:bg-action-hover",
          )}>Sign in</a
        >
      {/if}
    </div>
  </div>
</div>
