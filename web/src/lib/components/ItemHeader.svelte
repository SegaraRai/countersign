<script lang="ts">
  import { style } from "stillwind/svelte";

  import KindBadge from "#lib/components/KindBadge.svelte";
  import StatePill from "#lib/components/StatePill.svelte";
  import Time from "#lib/components/Time.svelte";
  import type { Tone, When } from "#lib/types.ts";

  let {
    kind,
    id,
    headline,
    tone,
    label,
    detail,
    time,
  }: {
    kind: "approval" | "question";
    id: string;
    headline: string;
    tone: Tone;
    label: string;
    detail?: string | null;
    time?: When | null;
  } = $props();
</script>

<header {...style("mb-5")}>
  <div {...style("flex mb-2 items-center gap-2")}>
    <KindBadge {kind} />
    <span {...style("truncate font-mono text-[0.6875rem] text-muted")} title="Request id">{id}</span
    >
  </div>
  <h1
    {...style("text-foreground text-xl leading-snug font-semibold tracking-tight wrap-break-word")}
  >
    {headline}
  </h1>
  <div {...style("flex mt-3 flex-wrap items-center gap-x-3 gap-y-1.5 text-sm")}>
    <StatePill {tone} {label} />
    {#if detail}
      <span {...style("text-foreground-secondary")}>{detail}</span>
    {/if}
    {#if time}
      <span {...style("text-muted")}>
        {time.label}
        <Time at={time.at} />
        (<Time at={time.at} mode="relative" />)
      </span>
    {/if}
  </div>
</header>
