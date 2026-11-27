<script lang="ts">
  import { enhance } from "$app/forms";
  import { style } from "stillwind/svelte";

  import Banner from "#lib/components/Banner.svelte";
  import Button from "#lib/components/Button.svelte";
  import PageHeader from "#lib/components/PageHeader.svelte";
  import Time from "#lib/components/Time.svelte";
  import { Submission } from "#lib/submit.svelte.ts";

  import type { PageProps } from "./$types";

  let { form }: PageProps = $props();

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
    "flex size-6 shrink-0 items-center justify-center text-action text-xs font-semibold bg-action-soft rounded-full",
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
  <ol {...style("flex p-5 flex-col gap-4 bg-surface rounded-panel border border-border")}>
    <li {...style("flex gap-3")}>
      <span {...style(step)}>1</span>
      <p {...style("text-sm leading-relaxed")}>Get a one-time code here.</p>
    </li>
    <li {...style("flex gap-3")}>
      <span {...style(step)}>2</span>
      <p {...style("text-sm leading-relaxed")}>
        Send it to countersign from the chat app. On Discord, run
        <code {...style("px-1 py-0.5 font-mono text-xs bg-surface-hover rounded")}
          >/countersign-link</code
        >
        and paste the code.
      </p>
    </li>
    <li {...style("flex gap-3")}>
      <span {...style(step)}>3</span>
      <p {...style("text-sm leading-relaxed")}>
        Chat buttons now act as you. Linking an account that is already linked moves it to you.
      </p>
    </li>
  </ol>

  <section
    {...style(
      "flex p-5 flex-col items-center justify-center gap-4 text-center bg-surface rounded-panel border border-border",
    )}
  >
    {#if failure}
      <Banner>{failure}</Banner>
    {/if}
    {#if code}
      <p {...style("text-muted text-xs font-medium tracking-wider uppercase")}>Your code</p>
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
      <p {...style("text-muted text-xs leading-relaxed")}>
        Valid once, until <Time at={code.expires} /> (<Time at={code.expires} mode="relative" />).
        Getting a new code cancels this one.
      </p>
    {:else}
      <span
        aria-hidden="true"
        {...style(
          "flex size-11 items-center justify-center text-action bg-action-soft rounded-full",
        )}
      >
        <span {...style("icon-lg icon-lucide--link")}></span>
      </span>
    {/if}
    <form method="POST" use:enhance={issuing.enhance}>
      <Button variant={code ? "secondary" : "primary"} disabled={issuing.busy}>
        {code ? "Get a new code" : "Get a code"}
      </Button>
    </form>
  </section>
</div>
