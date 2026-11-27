<script lang="ts">
  import { useClock } from "#lib/clock.svelte.ts";
  import { formatTime, relative, shortTime } from "#lib/time.ts";

  let {
    at,
    mode = "full",
  }: {
    at: string | null | undefined;
    /**
     * `relative` shows "in 4 min", `short` "18:45" (with the date when not
     * today), both with the full time as a tooltip.
     */
    mode?: "full" | "relative" | "short";
  } = $props();

  const clock = useClock();
  const full = $derived(at ? formatTime(at, clock.local) : "—");
</script>

{#if at}
  <time datetime={at} title={full}
    >{mode === "relative"
      ? relative(at, clock.now)
      : mode === "short"
        ? shortTime(at, clock.now, clock.local)
        : full}</time
  >
{:else}
  —
{/if}
