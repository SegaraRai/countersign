<script lang="ts">
  import { style } from "stillwind/svelte";

  let {
    title,
    description,
  }: {
    title: string;
    description?: string;
  } = $props();
</script>

<div
  {...style(
    "flex px-6 py-10 flex-col items-center justify-center text-center bg-surface rounded-panel border border-border",
  )}
>
  <span
    aria-hidden="true"
    {...style(
      "flex mb-3 size-9 items-center justify-center text-good bg-good-soft rounded-full border border-good/20",
    )}
  >
    <span {...style("icon-md icon-lucide--check")}></span>
  </span>
  <p {...style("text-foreground text-sm font-medium")}>{title}</p>
  {#if description}
    <p {...style("mt-1 max-w-sm text-muted text-xs leading-relaxed")}>{description}</p>
  {/if}
</div>
