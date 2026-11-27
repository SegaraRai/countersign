<script lang="ts">
  import { style } from "stillwind/svelte";

  import { refreshEvery } from "#lib/refresh.svelte.ts";

  import type { PageProps } from "./$types";
  import Approval from "./Approval.svelte";
  import Question from "./Question.svelte";

  let { data, form }: PageProps = $props();

  // A decision elsewhere (chat, another approver) shows up here too.
  refreshEvery(20, "app:request");

  const failure = $derived(
    form && typeof form.error === "string" ? { form: form.form, error: form.error } : null,
  );
  const headline = $derived(
    data.item.kind === "approval" ? data.item.p.headline : data.item.headline,
  );
</script>

<svelte:head>
  <title>{headline} · countersign</title>
</svelte:head>

<a
  href="/"
  {...style(
    "inline-flex mb-5 items-center gap-1 text-muted text-sm transition-colors hover:text-foreground",
  )}
>
  <span aria-hidden="true" {...style("icon-sm icon-lucide--chevron-left")}></span>
  All requests
</a>

{#if data.item.kind === "approval"}
  <Approval item={data.item} {failure} />
{:else}
  <Question item={data.item} {failure} />
{/if}
