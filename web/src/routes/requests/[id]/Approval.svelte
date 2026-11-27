<script lang="ts">
  import { enhance } from "$app/forms";
  import { style } from "stillwind/svelte";

  import Banner from "#lib/components/Banner.svelte";
  import Button from "#lib/components/Button.svelte";
  import Card from "#lib/components/Card.svelte";
  import Details from "#lib/components/Details.svelte";
  import Field from "#lib/components/Field.svelte";
  import Grant from "#lib/components/Grant.svelte";
  import ItemHeader from "#lib/components/ItemHeader.svelte";
  import Time from "#lib/components/Time.svelte";
  import { control } from "#lib/styles.ts";
  import { Submission } from "#lib/submit.svelte.ts";
  import type { ApprovalPage } from "#lib/types.ts";

  let {
    item,
    failure,
  }: {
    item: ApprovalPage;
    failure: { form: string; error: string } | null;
  } = $props();

  const p = $derived(item.p);
  const decisions = $derived(p.status.decisions ?? []);
  const uses = $derived(p.status.uses ?? []);
  const rows = $derived([
    ...(p.action?.type === "lines" ? p.action.lines : []),
    ...p.facts,
    ...(p.claims ?? []).map((c) => ({ ...c, unverified: item.claims_note })),
  ]);

  const deciding = new Submission();
  const revoking = new Submission();
</script>

<div {...style("grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem] lg:items-start")}>
  <div {...style("flex min-w-0 flex-col gap-6")}>
    <article {...style("p-5 bg-surface rounded-panel border border-border sm:p-6")}>
      <ItemHeader
        kind="approval"
        id={item.id}
        headline={p.headline}
        tone={p.status.tone}
        label={p.status.label}
        detail={p.status.detail}
        time={p.status.time}
      />

      <div {...style("flex flex-col gap-5")}>
        {#if p.status.tone === "waiting"}
          <Grant grant={p.grant} tone="waiting" />
        {:else if p.status.tone === "good"}
          <Grant grant={p.grant} label="Allowed" tone="good" />
        {/if}

        {#if item.sensitive}
          <Banner tone="info">
            Sensitive: chat channels show only that this request exists. This page shows everything.
          </Banner>
        {/if}

        {#if p.action?.type === "command"}
          <pre
            {...style(
              "overflow-x-auto px-4 py-3.5 font-mono text-[0.8125rem]/relaxed text-foreground wrap-break-word whitespace-pre-wrap bg-code rounded-control border border-border",
            )}><span {...style("text-muted select-none")}>$ </span>{p.action.line}</pre>
        {/if}

        {#if rows.length > 0}
          <Details items={rows} />
        {/if}

        {#if p.status.needs}
          <p {...style("text-muted text-xs")}>
            Needs <span {...style("text-foreground-secondary font-medium")}>{p.status.needs}</span>.
          </p>
        {/if}

        {#each p.notes ?? [] as note, i (i)}
          <Banner tone="info">{note}</Banner>
        {/each}

        {#if p.audit && p.audit.length > 0}
          <details {...style("group pt-4 border-border border-t")}>
            <summary
              {...style(
                "flex items-center gap-1.5 text-muted text-xs font-medium cursor-pointer select-none hover:text-foreground",
              )}
            >
              <span
                aria-hidden="true"
                {...style(
                  "icon-sm icon-lucide--chevron-right transition-transform group-open:rotate-90",
                )}
              ></span>
              <span aria-hidden="true" {...style("icon-sm icon-lucide--fingerprint")}></span>
              Identifiers and policy match
            </summary>
            <div {...style("mt-3")}>
              <Details items={p.audit} mono />
            </div>
          </details>
        {/if}
      </div>
    </article>

    {#if decisions.length > 0}
      <Card title="Decisions">
        <ol {...style("flex flex-col gap-4")}>
          {#each decisions as d, i (i)}
            <li {...style("flex gap-3")}>
              <span
                aria-hidden="true"
                data-approved={d.approved}
                {...style("flex size-7 shrink-0 items-center justify-center rounded-full", {
                  "data-[approved=true]:": "text-good bg-good-soft",
                  "data-[approved=false]:": "text-bad bg-bad-soft",
                })}
              >
                <span
                  data-approved={d.approved}
                  {...style("icon-sm", {
                    "data-[approved=true]:": "icon-lucide--check",
                    "data-[approved=false]:": "icon-lucide--x",
                  })}
                ></span>
              </span>
              <div {...style("min-w-0 flex-1")}>
                <p {...style("text-foreground text-sm")}>
                  <span {...style("font-medium")}>{d.who}</span>
                  {d.approved ? "approved" : "denied"}
                  <span {...style("text-muted")}>via {d.via} · {d.assurance}</span>
                </p>
                <p {...style("text-muted text-xs")}><Time at={d.at} /></p>
                {#if d.comment}
                  <p
                    {...style(
                      "mt-1.5 px-3 py-2 text-foreground-secondary text-sm bg-surface-subtle rounded-control border border-border",
                    )}
                  >
                    {d.comment}
                  </p>
                {/if}
              </div>
            </li>
          {/each}
        </ol>
      </Card>
    {/if}

    {#if uses.length > 0}
      <Card title="Approved under this window" description="Later requests this approval covered.">
        <ul {...style("flex flex-col divide-y divide-border")}>
          {#each uses as u, i (i)}
            <li {...style("flex py-2 flex-col gap-0.5 first:pt-0 last:pb-0 sm:flex-row sm:gap-4")}>
              <span {...style("shrink-0 text-muted text-xs sm:w-36 sm:pt-0.5")}
                ><Time at={u.at} /></span
              >
              <code {...style("min-w-0 font-mono text-foreground text-xs wrap-break-word")}
                >{u.what}</code
              >
            </li>
          {/each}
        </ul>
      </Card>
    {/if}
  </div>

  <aside {...style("flex flex-col gap-4 lg:sticky lg:top-20")}>
    {#if item.can_decide}
      <section {...style("p-5 bg-surface rounded-panel border border-border-strong shadow-xs")}>
        <h2 {...style("mb-3.5 text-foreground text-sm font-semibold")}>Your decision</h2>
        {#if failure?.form === "decide"}
          <div {...style("mb-3")}><Banner>{failure.error}</Banner></div>
        {/if}
        <form
          method="POST"
          action="?/decide"
          use:enhance={deciding.enhance}
          use:deciding.keep
          {...style("flex flex-col gap-4")}
        >
          <Field label="Comment" hint="optional">
            <textarea
              name="comment"
              rows="2"
              maxlength="500"
              placeholder="Why, for the record"
              {...style(control, "resize-y")}></textarea>
          </Field>
          <div {...style("grid grid-cols-2 gap-2.5")}>
            <Button
              variant="approve"
              size="lg"
              name="verdict"
              value="approve"
              disabled={deciding.busy}
            >
              <span aria-hidden="true" {...style("icon-sm icon-lucide--check")}></span>
              Approve
            </Button>
            <Button variant="deny" size="lg" name="verdict" value="deny" disabled={deciding.busy}>
              <span aria-hidden="true" {...style("icon-sm icon-lucide--x")}></span>
              Deny
            </Button>
          </div>
          {#if item.approve_needs_reauth}
            <p
              {...style(
                "flex pt-3 gap-2 text-muted text-xs leading-relaxed border-border border-t",
              )}
            >
              <span aria-hidden="true" {...style("icon-sm icon-lucide--lock mt-0.5 shrink-0")}
              ></span>
              Approving needs a fresh sign-in: you will sign in again and come back here. Denying does
              not.
            </p>
          {:else if item.fresh_until}
            <p
              {...style(
                "flex pt-3 gap-2 text-muted text-xs leading-relaxed border-border border-t",
              )}
            >
              <span
                aria-hidden="true"
                {...style("icon-sm icon-lucide--shield-check mt-0.5 shrink-0 text-good")}
              ></span>
              <span>Freshly signed in: you can approve until <Time at={item.fresh_until} />.</span>
            </p>
          {/if}
        </form>
      </section>
    {:else if item.can_revoke}
      <section {...style("p-5 bg-surface rounded-panel border border-border")}>
        <h2 {...style("mb-1 text-foreground text-sm font-semibold")}>Access is active</h2>
        <p {...style("mb-4 text-muted text-xs leading-relaxed")}>
          Revoking ends it now, before it would expire.
        </p>
        {#if failure?.form === "revoke"}
          <div {...style("mb-3")}><Banner>{failure.error}</Banner></div>
        {/if}
        <form method="POST" action="?/revoke" use:enhance={revoking.enhance}>
          <Button variant="danger" disabled={revoking.busy} data-confirm="Revoke this access now?">
            <span aria-hidden="true" {...style("icon-sm icon-lucide--ban")}></span>
            Revoke access now
          </Button>
        </form>
      </section>
    {:else if item.cannot_decide}
      <section
        {...style(
          "flex p-4 gap-2.5 text-muted text-sm bg-surface-subtle rounded-panel border border-border",
        )}
      >
        <span aria-hidden="true" {...style("icon-md icon-lucide--eye mt-0.5 shrink-0")}></span>
        <p {...style("leading-relaxed")}>{item.cannot_decide}</p>
      </section>
    {/if}
  </aside>
</div>
