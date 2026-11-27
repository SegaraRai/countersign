<script lang="ts">
  import { enhance } from "$app/forms";
  import { style } from "stillwind/svelte";

  import Banner from "#lib/components/Banner.svelte";
  import Button from "#lib/components/Button.svelte";
  import Card from "#lib/components/Card.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Time from "#lib/components/Time.svelte";
  import { controlSm, heading } from "#lib/styles.ts";
  import { Submission } from "#lib/submit.svelte.ts";

  import type { PageProps } from "./$types";

  let { data, form }: PageProps = $props();

  const admin = $derived(data.admin);
  const acting = new Submission();
  const failure = $derived(form && "error" in form ? form.error : null);

  const th = style("px-4 py-2.5 text-left text-muted text-xs font-medium whitespace-nowrap");
  const td = style("px-4 py-3 align-top");
  const chip = style(
    "px-1.5 py-0.5 font-mono text-[0.6875rem] text-foreground-secondary bg-surface-hover rounded",
  );
</script>

<svelte:head>
  <title>People · countersign</title>
</svelte:head>

<PageHeader
  title="People and workloads"
  description="Persons, workloads, groups and roles come from the configuration. Suspensions take effect at once: a suspended person cannot sign in, decide or answer, their pending approvals stop counting, and a suspended workload's open requests are withdrawn or revoked. Lifting a suspension needs a fresh sign-in."
/>

{#if failure}
  <div {...style("mb-5")}><Banner>{failure}</Banner></div>
{/if}

<section {...style("mb-10")}>
  <div {...style("overflow-x-auto bg-surface rounded-panel border border-border")}>
    <table {...style("w-full text-sm")}>
      <thead {...style("bg-surface-subtle border-border border-b")}>
        <tr>
          <th {...style(th)}>Who</th>
          <th {...style(th)}>Status</th>
          <th {...style(th)}>Groups and roles</th>
          {#if admin.admin}<th {...style(th)}><span {...style("sr-only")}>Actions</span></th>{/if}
        </tr>
      </thead>
      <tbody {...style("divide-y divide-border")}>
        {#each admin.actors as a (a.id)}
          <tr>
            <td {...style(td)}>
              <div {...style("flex items-center gap-2")}>
                <span
                  aria-hidden="true"
                  data-kind={a.kind}
                  {...style("icon-sm shrink-0 text-muted", {
                    "data-[kind=person]:": "icon-lucide--user",
                    "data-[kind=workload]:": "icon-lucide--bot",
                  })}
                ></span>
                <span {...style("text-foreground font-medium")}>{a.id}</span>
                {#if a.name !== a.id}<span {...style("text-muted")}>{a.name}</span>{/if}
              </div>
              {#if a.owners.length > 0}
                <p {...style("mt-1 ml-6 text-muted text-xs")}>owned by {a.owners.join(", ")}</p>
              {/if}
            </td>
            <td {...style(td)}>
              {#if a.suspension}
                <span
                  {...style(
                    "inline-flex h-6 px-2 items-center text-bad text-xs font-medium bg-bad-soft rounded-full",
                  )}>Suspended</span
                >
                <p {...style("mt-1 text-muted text-xs")}>
                  by {a.suspension.by}, <Time at={a.suspension.since} mode="relative" />
                  {#if a.suspension.reason}<br />“{a.suspension.reason}”{/if}
                </p>
              {:else if a.active}
                <span
                  {...style(
                    "inline-flex h-6 px-2 items-center text-good text-xs font-medium bg-good-soft rounded-full",
                  )}>Active</span
                >
              {:else}
                <span
                  {...style(
                    "inline-flex h-6 px-2 items-center text-quiet text-xs font-medium bg-quiet-soft rounded-full",
                  )}>Inactive</span
                >
                <p {...style("mt-1 text-muted text-xs")}>no active owner</p>
              {/if}
            </td>
            <td {...style(td)}>
              <div {...style("flex max-w-xs flex-wrap gap-1")}>
                {#each a.roles as r (r)}
                  <span
                    {...style(
                      "px-1.5 py-0.5 font-mono text-[0.6875rem] text-action font-medium bg-action-soft rounded",
                    )}>{r}</span
                  >
                {/each}
                {#each a.groups as g (g)}
                  <span {...style(chip)}>{g}</span>
                {/each}
                {#if a.roles.length === 0 && a.groups.length === 0}
                  <span {...style("text-muted text-xs")}>—</span>
                {/if}
              </div>
            </td>
            {#if admin.admin}
              <td {...style(td, "text-right")}>
                <form
                  method="POST"
                  use:enhance={acting.enhance}
                  {...style("flex flex-wrap items-center justify-end gap-2")}
                >
                  <input type="hidden" name="actor" value={a.id} />
                  {#if a.suspension}
                    <Button
                      variant="secondary"
                      size="sm"
                      name="action"
                      value="reinstate"
                      disabled={acting.busy}
                    >
                      Lift suspension
                    </Button>
                  {:else}
                    <input
                      type="text"
                      name="reason"
                      placeholder="Reason"
                      maxlength="500"
                      aria-label="Reason for suspending {a.id}"
                      {...style(controlSm)}
                    />
                    <Button
                      variant="danger"
                      size="sm"
                      name="action"
                      value="suspend"
                      disabled={acting.busy}
                      data-confirm="Suspend {a.id}? It takes effect at once."
                    >
                      Suspend
                    </Button>
                  {/if}
                  {#if a.kind === "person"}
                    <Button
                      variant="ghost"
                      size="sm"
                      name="action"
                      value="revoke-approved-by"
                      disabled={acting.busy}
                      title="Revoke every active approval {a.id} gave"
                      data-confirm="Revoke every active approval {a.id} gave?"
                    >
                      Revoke approvals
                    </Button>
                  {/if}
                </form>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<section {...style("mb-10")}>
  <h2 {...style(heading)}>Chat links</h2>
  {#if admin.links.length === 0}
    <p {...style("text-muted text-sm")}>No chat accounts are linked.</p>
  {:else}
    <div {...style("overflow-x-auto bg-surface rounded-panel border border-border")}>
      <table {...style("w-full text-sm")}>
        <thead {...style("bg-surface-subtle border-border border-b")}>
          <tr>
            <th {...style(th)}>Channel</th>
            <th {...style(th)}>Account</th>
            <th {...style(th)}>Person</th>
            <th {...style(th)}>Linked</th>
            {#if admin.admin}<th {...style(th)}><span {...style("sr-only")}>Actions</span></th>{/if}
          </tr>
        </thead>
        <tbody {...style("divide-y divide-border")}>
          {#each admin.links as l (l.channel + l.external_id)}
            <tr>
              <td {...style(td)}>{l.channel}</td>
              <td {...style(td)}><code {...style("font-mono text-xs")}>{l.external_id}</code></td>
              <td {...style(td)}>{l.person}</td>
              <td {...style(td, "text-muted text-xs whitespace-nowrap")}
                ><Time at={l.linked_at} /></td
              >
              {#if admin.admin}
                <td {...style(td, "text-right")}>
                  <form method="POST" use:enhance={acting.enhance}>
                    <input type="hidden" name="channel" value={l.channel} />
                    <input type="hidden" name="external_id" value={l.external_id} />
                    <Button
                      variant="ghost"
                      size="sm"
                      name="action"
                      value="unlink"
                      disabled={acting.busy}
                      data-confirm="Unlink this {l.channel} account from {l.person}?"
                    >
                      Unlink
                    </Button>
                  </form>
                </td>
              {/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<Card title="Admin actions" description="The latest 50, newest first.">
  {#if admin.actions.length === 0}
    <p {...style("text-muted text-sm")}>None yet.</p>
  {:else}
    <ol {...style("flex flex-col divide-y divide-border")}>
      {#each admin.actions as a, i (i)}
        <li {...style("flex py-2.5 flex-col gap-0.5 first:pt-0 last:pb-0 sm:flex-row sm:gap-4")}>
          <span {...style("shrink-0 text-muted text-xs sm:w-36 sm:pt-0.5")}><Time at={a.at} /></span
          >
          <p {...style("min-w-0 text-sm wrap-break-word")}>
            <span {...style("font-medium")}>{a.by}</span>
            <code {...style(chip)}>{a.action}</code>
            {a.target}
            {#if a.detail}<span {...style("text-muted")}>— {a.detail}</span>{/if}
          </p>
        </li>
      {/each}
    </ol>
  {/if}
</Card>
