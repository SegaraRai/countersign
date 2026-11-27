<script lang="ts">
  import { style } from "stillwind/svelte";
  import type { Snippet } from "svelte";

  let {
    label,
    hint,
    required = false,
    description,
    children,
  }: {
    label: string;
    hint?: string | null;
    required?: boolean;
    description?: string | null;
    children: Snippet;
  } = $props();
</script>

<label {...style("flex flex-col gap-1.5")}>
  <span {...style("flex items-baseline justify-between gap-2")}>
    <span {...style("text-foreground-secondary text-xs font-medium")}>
      {label}{#if required}<span {...style("ml-1 font-normal text-muted")}>(required)</span>{/if}
    </span>
    {#if hint}
      <span {...style("truncate text-muted text-xs")}>{hint}</span>
    {/if}
  </span>
  {#if description}
    <span {...style("text-muted text-xs leading-relaxed")}>{description}</span>
  {/if}
  {@render children()}
</label>
