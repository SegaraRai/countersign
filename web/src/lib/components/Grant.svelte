<script lang="ts">
  import { style } from "stillwind/svelte";

  let {
    grant,
    label = "If you approve",
  }: {
    /** What approving allows, in words. */
    grant: string;
    /** `null`: the sentence says it all. */
    label?: string | null;
  } = $props();
</script>

<div
  {...style(
    "flex px-4 py-3 items-start gap-3 bg-waiting-soft rounded-control border border-waiting/40",
  )}
>
  <span aria-hidden="true" {...style("icon-md icon-lucide--key-round mt-0.5 shrink-0 text-waiting")}
  ></span>
  <p {...style("text-foreground text-sm leading-relaxed")}>
    {#if label}<strong {...style("font-semibold")}>{label}:</strong>{/if}
    {grant}
  </p>
</div>
