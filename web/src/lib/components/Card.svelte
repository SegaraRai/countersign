<script lang="ts">
  import { style } from "stillwind/svelte";
  import type { Snippet } from "svelte";

  let {
    title,
    description,
    actions,
    children,
  }: {
    title?: string;
    description?: string;
    actions?: Snippet;
    children: Snippet;
  } = $props();
</script>

<section {...style("p-5 bg-surface rounded-panel border border-border")}>
  {#if title || description || actions}
    <div {...style("flex mb-4 flex-wrap items-start justify-between gap-3")}>
      <div {...style("min-w-0")}>
        {#if title}
          <h2 {...style("text-foreground text-sm font-semibold")}>{title}</h2>
        {/if}
        {#if description}
          <p {...style("mt-0.5 text-muted text-xs leading-relaxed")}>{description}</p>
        {/if}
      </div>
      {#if actions}
        <div {...style("flex shrink-0 items-center gap-2")}>
          {@render actions()}
        </div>
      {/if}
    </div>
  {/if}
  {@render children()}
</section>
