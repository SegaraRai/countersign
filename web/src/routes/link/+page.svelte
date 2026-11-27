<script lang="ts">
  import { enhance } from "$app/forms";
  import { style } from "stillwind/svelte";

  import Banner from "#lib/components/Banner.svelte";
  import Button from "#lib/components/Button.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import PushNotifications from "#lib/components/PushNotifications.svelte";
  import Time from "#lib/components/Time.svelte";
  import { Submission } from "#lib/submit.svelte.ts";

  import type { PageProps } from "./$types";

  let { data, form }: PageProps = $props();

  const issuing = new Submission();
  const code = $derived(form && "done" in form ? form.done : null);
  const failure = $derived(form && "error" in form ? form.error : null);

  let copied = $state(false);
  async function copy() {
    if (!code) {
      return;
    }
    await navigator.clipboard.writeText(code.code);
    copied = true;
    setTimeout(() => (copied = false), 2000);
  }

  const step = style(
    "flex size-6 shrink-0 items-center justify-center text-action text-xs font-semibold bg-action-soft rounded-full border border-action/25",
  );
</script>

<svelte:head>
  <title>Chat account · countersign</title>
</svelte:head>

<PageHeader
  title="Link a chat account"
  description="Linking lets you approve and deny from chat buttons, where a policy allows it."
/>

<div {...style("grid gap-6 md:grid-cols-2")}>
  <ol {...style("flex p-6 flex-col gap-5 bg-surface rounded-panel border border-border")}>
    <li {...style("flex gap-3")}>
      <span {...style(step)}>1</span>
      <p {...style("text-foreground-secondary text-sm leading-relaxed")}>
        Get a one-time code here.
      </p>
    </li>
    <li {...style("flex gap-3")}>
      <span {...style(step)}>2</span>
      <p {...style("text-foreground-secondary text-sm leading-relaxed")}>
        Send it to countersign from the chat app. On Discord or Slack, run
        <code
          {...style(
            "px-1.5 py-0.5 font-mono text-foreground text-xs bg-code rounded border border-border/70",
          )}>/countersign-link</code
        >
        and paste the code.
      </p>
    </li>
    <li {...style("flex gap-3")}>
      <span {...style(step)}>3</span>
      <p {...style("text-foreground-secondary text-sm leading-relaxed")}>
        Chat buttons now act as you. Linking an account that is already linked moves it to you.
      </p>
    </li>
  </ol>

  <section
    {...style(
      "flex p-6 flex-col items-center justify-center gap-4 text-center bg-surface rounded-panel border border-border",
    )}
  >
    {#if failure}
      <Banner>{failure}</Banner>
    {/if}
    {#if code}
      <p {...style("text-[0.6875rem] text-muted font-semibold tracking-[0.08em] uppercase")}>
        Your code
      </p>
      <div {...style("flex items-center gap-2")}>
        <code
          data-code
          {...style(
            "px-4 py-2 font-mono text-2xl text-foreground font-semibold tracking-[0.12em] bg-code rounded-control border border-border select-all",
          )}>{code.code}</code
        >
        <Button variant="ghost" type="button" aria-label="Copy the code" onclick={copy}>
          <span
            aria-hidden="true"
            data-copied={copied}
            {...style("icon-md", {
              "data-[copied=false]:": "icon-lucide--copy",
              "data-[copied=true]:": "icon-lucide--check text-good",
            })}
          ></span>
        </Button>
      </div>
      <p {...style("max-w-xs text-muted text-xs leading-relaxed")}>
        Valid once, until <Time at={code.expires} /> (<Time at={code.expires} mode="relative" />).
        Getting a new code cancels this one.
      </p>
    {:else}
      <span
        aria-hidden="true"
        {...style(
          "flex size-11 items-center justify-center text-action bg-action-soft rounded-full border border-action/25",
        )}
      >
        <span {...style("icon-lg icon-lucide--link")}></span>
      </span>
      <div>
        <h2 {...style("text-foreground text-sm font-semibold")}>One-time link code</h2>
        <p {...style("mt-1 max-w-xs text-muted text-xs leading-relaxed")}>
          Generate a short-lived code to connect your chat account to countersign.
        </p>
      </div>
    {/if}
    <form method="POST" use:enhance={issuing.enhance}>
      <Button variant={code ? "secondary" : "primary"} disabled={issuing.busy}>
        {code ? "Get a new code" : "Get a code"}
      </Button>
    </form>
  </section>
</div>

{#if data.me}
  <PushNotifications csrf={data.me.csrf} />
{/if}
