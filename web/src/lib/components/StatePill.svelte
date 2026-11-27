<script lang="ts">
  import { style } from "stillwind/svelte";

  import type { Tone } from "#lib/types.ts";

  let { tone, label }: { tone: Tone; label: string } = $props();
</script>

<span
  data-tone={tone}
  {...style(
    "inline-flex h-6 px-2.5 items-center gap-1.5 text-xs font-medium whitespace-nowrap rounded-full border",
    {
      "data-[tone=waiting]:": "text-waiting bg-waiting-soft border-waiting/20",
      "data-[tone=asking]:": "text-asking bg-asking-soft border-asking/20",
      "data-[tone=good]:": "text-good bg-good-soft border-good/20",
      "data-[tone=done]:": "text-done bg-done-soft border-done/20",
      "data-[tone=bad]:": "text-bad bg-bad-soft border-bad/20",
      "data-[tone=muted]:": "text-quiet bg-quiet-soft border-border",
    },
  )}
>
  <span aria-hidden="true" {...style("size-1.5 shrink-0 bg-current rounded-full")}></span>
  {label}
</span>
