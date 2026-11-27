<script lang="ts">
  import { style } from "stillwind/svelte";

  let {
    grant,
    label = "If you approve",
    tone = "waiting",
  }: {
    /** What approving allows, in words. */
    grant: string;
    /** `null`: the sentence says it all. */
    label?: string | null;
    tone?: "waiting" | "good" | "info";
  } = $props();
</script>

<div
  data-tone={tone}
  {...style("flex px-3.5 py-2.5 items-start gap-2.5 rounded-control border", {
    "data-[tone=waiting]:": "bg-waiting-soft/75 border-waiting/25",
    "data-[tone=good]:": "bg-good-soft/75 border-good/25",
    "data-[tone=info]:": "bg-surface-subtle border-border",
  })}
>
  <span
    aria-hidden="true"
    data-tone={tone}
    {...style("icon-sm mt-1 shrink-0", {
      "data-[tone=waiting]:": "icon-lucide--key-round text-waiting",
      "data-[tone=good]:": "icon-lucide--shield-check text-good",
      "data-[tone=info]:": "icon-lucide--info text-muted",
    })}
  ></span>
  <p {...style("text-foreground text-sm leading-relaxed")}>
    {#if label}<strong {...style("font-semibold")}>{label}:</strong>{/if}
    {grant}
  </p>
</div>
