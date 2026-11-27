<script lang="ts">
  import { style } from "stillwind/svelte";
  import type { Snippet } from "svelte";

  let {
    title,
    description,
    actions,
  }: {
    title: string;
    description?: string;
    actions?: Snippet;
  } = $props();
</script>

<div {...style("flex mb-7 flex-wrap items-end justify-between gap-3")}>
  <div {...style("min-w-0")}>
    <h1 {...style("text-2xl text-foreground font-semibold tracking-tight")}>{title}</h1>
    {#if description}
      <p {...style("mt-1.5 max-w-2xl text-muted text-sm leading-relaxed")}>{description}</p>
    {/if}
  </div>
  {#if actions}
    <div {...style("flex shrink-0 items-center gap-2")}>
      {@render actions()}
    </div>
  {/if}
</div>
