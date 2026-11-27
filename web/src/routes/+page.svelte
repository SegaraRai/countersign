<script lang="ts">
  import { style } from "stillwind/svelte";

  import EmptyState from "#lib/components/EmptyState.svelte";
  import KindBadge from "#lib/components/KindBadge.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import StatePill from "#lib/components/StatePill.svelte";
  import Time from "#lib/components/Time.svelte";
  import { refreshEvery } from "#lib/refresh.svelte.ts";
  import { heading } from "#lib/styles.ts";
  import type { Row } from "#lib/types.ts";

  import type { PageProps } from "./$types";

  let { data }: PageProps = $props();

  refreshEvery(15);

  const waiting = $derived(data.index.waiting);
  const active = $derived(data.index.active);
  const recent = $derived(data.index.recent);
</script>

<svelte:head>
  <title>{waiting.length > 0 ? `(${waiting.length}) ` : ""}Requests · countersign</title>
</svelte:head>

<PageHeader
  title="Requests"
  description="Approvals and questions waiting for you, access that is open now, and what happened recently."
/>

{#snippet card(r: Row)}
  <li>
    <a
      href="/requests/{r.id}"
      {...style(
        "relative flex overflow-hidden py-4 pr-4 pl-5 flex-col gap-3 bg-surface rounded-panel border border-border transition-colors sm:flex-row sm:items-center sm:gap-5",
        {
          "hover:": "bg-surface-subtle border-border-strong",
          "focus-visible:": "outline-2 outline-action outline-offset-2",
        },
      )}
    >
      <span
        aria-hidden="true"
        data-tone={r.tone}
        {...style("absolute inset-y-0 left-0 w-1", {
          "data-[tone=waiting]:": "bg-waiting",
          "data-[tone=asking]:": "bg-asking",
          "data-[tone=good]:": "bg-good",
        })}
      ></span>
      <div {...style("min-w-0 flex-1")}>
        <div {...style("flex mb-1.5 items-center gap-2")}>
          <KindBadge kind={r.kind} />
          <span {...style("text-muted text-xs")}>
            <Time at={r.created_at} mode="relative" />
          </span>
        </div>
        <p {...style("text-[0.9375rem]/snug text-foreground font-medium")}>
          {r.headline}
        </p>
        {#if r.summary}
          <p
            {...style(
              "truncate mt-1.5 px-2 py-1 font-mono text-foreground-secondary text-xs bg-code rounded",
            )}
          >
            {r.summary}
          </p>
        {/if}
      </div>
      <div {...style("flex shrink-0 items-center gap-3 sm:flex-col sm:items-end sm:gap-1.5")}>
        <StatePill tone={r.tone} label={r.label} />
        {#if r.time}
          <span {...style("text-muted text-xs whitespace-nowrap")}>
            {r.time.label}
            <Time at={r.time.at} mode="short" />
          </span>
        {/if}
      </div>
    </a>
  </li>
{/snippet}

<section {...style("mb-10")} aria-labelledby="waiting">
  <h2 id="waiting" {...style(heading, "flex items-center gap-2")}>
    Waiting
    {#if waiting.length > 0}
      <span
        {...style(
          "inline-flex h-5 min-w-5 px-1.5 items-center justify-center text-[0.6875rem] text-waiting tabular-nums bg-waiting-soft rounded-full",
        )}>{waiting.length}</span
      >
    {/if}
  </h2>

  {#if waiting.length === 0}
    <EmptyState
      title="Nothing is waiting for a decision or an answer."
      description="New requests appear here on their own."
    />
  {:else}
    <ul {...style("flex flex-col gap-3")}>
      {#each waiting as r (r.id)}
        {@render card(r)}
      {/each}
    </ul>
  {/if}
</section>

{#if active.length > 0}
  <section {...style("mb-10")} aria-labelledby="active">
    <h2 id="active" {...style(heading)}>Active now</h2>
    <ul {...style("flex flex-col gap-3")}>
      {#each active as r (r.id)}
        {@render card(r)}
      {/each}
    </ul>
  </section>
{/if}

<section aria-labelledby="recent">
  <h2 id="recent" {...style(heading)}>Recent</h2>
  {#if recent.length === 0}
    <p {...style("text-muted text-sm")}>Nothing has finished yet.</p>
  {:else}
    <ul
      {...style(
        "overflow-hidden bg-surface rounded-panel border border-border divide-y divide-border",
      )}
    >
      {#each recent as r (r.id)}
        <li>
          <a
            href="/requests/{r.id}"
            {...style(
              "flex px-4 py-3 flex-col gap-2 transition-colors sm:flex-row sm:items-center sm:gap-4",
              {
                "hover:": "bg-surface-subtle",
                "focus-visible:": "outline-2 outline-action -outline-offset-2",
              },
            )}
          >
            <div {...style("flex min-w-0 flex-1 items-center gap-3")}>
              <KindBadge kind={r.kind} />
              <div {...style("min-w-0")}>
                <p {...style("truncate text-foreground text-sm")}>{r.headline}</p>
                {#if r.summary}
                  <p {...style("truncate font-mono text-muted text-xs")}>{r.summary}</p>
                {/if}
              </div>
            </div>
            <div {...style("flex shrink-0 items-center gap-3")}>
              <StatePill tone={r.tone} label={r.label} />
              <span {...style("w-20 text-right text-muted text-xs whitespace-nowrap")}>
                <Time at={r.updated_at} mode="relative" />
              </span>
            </div>
          </a>
        </li>
      {/each}
    </ul>
  {/if}
</section>
