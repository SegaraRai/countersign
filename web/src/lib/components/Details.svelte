<script lang="ts">
  import { style } from "stillwind/svelte";

  import type { Detail } from "#lib/types.ts";

  type DetailItem = Detail & {
    /** Shown in a tooltip next to the label when the value is unverified. */
    unverified?: string;
  };

  let {
    items,
    mono = false,
  }: {
    items: DetailItem[];
    /** Values in monospace: identifiers, commands. */
    mono?: boolean;
  } = $props();
</script>

{#if items.length > 0}
  <dl
    {...style(
      "bg-surface-subtle/50 rounded-control border border-border/70 divide-y divide-border/60",
    )}
  >
    {#each items as d, i (i)}
      <div
        {...style(
          "grid px-3.5 py-2.5 gap-x-4 gap-y-0.5 sm:grid-cols-[minmax(8.5rem,11rem)_1fr] sm:items-baseline",
        )}
      >
        <dt {...style("flex items-center gap-1.5 text-muted text-xs font-medium")}>
          <span>{d.label}</span>
          {#if d.unverified}
            <span {...style("group relative inline-flex items-center")}>
              <button
                type="button"
                aria-label={d.unverified}
                title={d.unverified}
                {...style(
                  "inline-flex size-4 items-center justify-center text-waiting/80 rounded-full transition-colors cursor-help hover:text-waiting focus-visible:text-waiting focus-visible:outline-2 focus-visible:outline-action focus-visible:outline-offset-1",
                )}
              >
                <span aria-hidden="true" {...style("icon-xs icon-lucide--triangle-alert")}></span>
              </button>
              <span
                role="tooltip"
                {...style(
                  "absolute bottom-full left-0 z-10 mb-1.5 px-2.5 py-1 font-normal text-foreground text-xs whitespace-nowrap bg-surface rounded-md border border-border-strong opacity-0 shadow-md transition-opacity pointer-events-none group-focus-within:opacity-100 group-hover:opacity-100",
                )}
              >
                {d.unverified}
              </span>
            </span>
          {/if}
        </dt>
        <dd
          data-mono={mono}
          {...style("min-w-0 text-foreground text-sm wrap-break-word whitespace-pre-wrap", {
            "data-[mono=true]:": "font-mono text-xs",
          })}
        >
          {d.value}
        </dd>
      </div>
    {/each}
  </dl>
{/if}
