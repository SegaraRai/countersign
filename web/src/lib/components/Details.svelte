<script lang="ts">
  import { style } from "stillwind/svelte";
  import type { Snippet } from "svelte";

  import type { Detail } from "#lib/types.ts";

  let {
    items,
    mono = false,
    note,
  }: {
    items: Detail[];
    /** Values in monospace: identifiers, commands. */
    mono?: boolean;
    /** Shown next to every value. */
    note?: Snippet;
  } = $props();
</script>

{#if items.length > 0}
  <dl {...style("grid gap-x-6 gap-y-2.5 sm:grid-cols-[minmax(7rem,max-content)_1fr]")}>
    {#each items as d, i (i)}
      <dt {...style("text-muted text-xs font-medium sm:pt-0.5")}>{d.label}</dt>
      <dd
        data-mono={mono}
        {...style("min-w-0 text-foreground text-sm wrap-break-word whitespace-pre-wrap", {
          "data-[mono=true]:": "font-mono text-xs sm:pt-0.5",
        })}
      >
        {d.value}{#if note}{" "}{@render note()}{/if}
      </dd>
    {/each}
  </dl>
{/if}
