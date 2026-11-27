<script lang="ts">
  import { enhance } from "$app/forms";
  import { style } from "stillwind/svelte";

  import Banner from "#lib/components/Banner.svelte";
  import Button from "#lib/components/Button.svelte";
  import Card from "#lib/components/Card.svelte";
  import Field from "#lib/components/Field.svelte";
  import Grant from "#lib/components/Grant.svelte";
  import ItemHeader from "#lib/components/ItemHeader.svelte";
  import Time from "#lib/components/Time.svelte";
  import { check, control, heading } from "#lib/styles.ts";
  import { Submission } from "#lib/submit.svelte.ts";
  import type { QuestionPage } from "#lib/types.ts";

  let {
    item,
    failure,
  }: {
    item: QuestionPage;
    failure: { form: string; error: string } | null;
  } = $props();

  const q = $derived(item.q);
  const answering = new Submission();
  const declining = new Submission();

  const outcome = $derived.by(() => {
    const o = q.outcome;
    if (!o) {
      return null;
    }
    switch (o.kind) {
      case "answered":
        return { text: `Answered by ${o.by} via ${o.via} (${o.assurance})`, at: o.at };
      case "declined":
        return { text: `Declined by ${o.by} via ${o.via} (${o.assurance})`, at: o.at };
      case "expired":
        return { text: "No answer: it expired", at: o.at };
      case "withdrawn":
        return { text: "Withdrawn by the asker", at: o.at };
    }
  });

  const dt = style("text-muted text-xs font-medium");
  const dd = style("mt-0.5 text-foreground text-sm wrap-break-word");
</script>

<div {...style("grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem] lg:items-start")}>
  <div {...style("flex min-w-0 flex-col gap-6")}>
    <article {...style("p-5 bg-surface rounded-panel border border-border sm:p-6")}>
      <ItemHeader
        kind="question"
        id={item.id}
        headline={item.headline}
        tone={item.status.tone}
        label={item.status.label}
        detail={item.status.detail}
        time={item.status.time}
      />

      <div {...style("flex flex-col gap-5")}>
        {#if item.can_answer}
          <Grant grant={item.grant} label={null} tone="info" />
        {/if}

        <p {...style("text-muted text-sm leading-relaxed")}>
          Asked by client <code
            {...style(
              "px-1.5 py-0.5 font-mono text-foreground-secondary text-xs bg-surface-subtle rounded border border-border/60",
            )}>{q.asker}</code
          >{#if q.asker_actor}
            for <code
              {...style(
                "px-1.5 py-0.5 font-mono text-foreground-secondary text-xs bg-surface-subtle rounded border border-border/60",
              )}>{q.asker_actor}</code
            >{/if}. The text below comes from the asker and is unverified.
        </p>

        {#if q.confidential_question}
          <Banner tone="info">
            Confidential question: its text and answer are removed once they are no longer needed,
            and it is never shown in chat.
          </Banner>
        {/if}

        {#if q.message !== null}
          <div
            {...style(
              "px-4 py-3.5 text-[0.9375rem]/relaxed text-foreground wrap-break-word whitespace-pre-wrap bg-surface-subtle rounded-r-control border-y border-y-border border-r border-r-border border-l-2 border-l-asking",
            )}
          >
            {q.message}
          </div>
        {:else if q.removed}
          <p {...style("text-muted text-sm italic")}>Content removed (confidential).</p>
        {:else if item.read_needs_reauth}
          <div
            {...style(
              "flex px-4 py-3 flex-wrap items-center justify-between gap-3 bg-surface-subtle rounded-control border border-border",
            )}
          >
            <p {...style("text-foreground-secondary text-sm")}>
              Reading this confidential question needs a fresh sign-in.
            </p>
            <a
              href="/login?next={encodeURIComponent(`/requests/${item.id}`)}&fresh=1"
              data-sveltekit-reload
              {...style(
                "inline-flex h-8 px-3 items-center gap-1.5 text-action-foreground text-xs font-medium bg-action rounded-control hover:bg-action-hover",
              )}
            >
              <span aria-hidden="true" {...style("icon-sm icon-lucide--lock-open")}></span>
              Sign in again to read it
            </a>
          </div>
        {:else}
          <p {...style("text-muted text-sm italic")}>
            Confidential: only its responders can read it.
          </p>
        {/if}

        {#if q.context.length > 0}
          <div>
            <h2 {...style(heading)}>Context</h2>
            <dl
              {...style(
                "bg-surface-subtle/50 rounded-control border border-border/70 divide-y divide-border/60",
              )}
            >
              {#each q.context as [k, v], i (i)}
                <div
                  {...style(
                    "grid px-3.5 py-2 gap-x-4 gap-y-0.5 sm:grid-cols-[minmax(8rem,10.5rem)_1fr] sm:items-baseline",
                  )}
                >
                  <dt {...style("text-muted text-xs font-medium")}>{k}</dt>
                  <dd
                    {...style(
                      "min-w-0 text-foreground text-sm wrap-break-word whitespace-pre-wrap",
                    )}
                  >
                    {v}
                  </dd>
                </div>
              {/each}
            </dl>
          </div>
        {/if}
      </div>
    </article>

    {#if q.answer.length > 0 || q.answer_hidden}
      <Card title={q.answer_confidential ? "Answer (confidential)" : "Answer"}>
        {#if q.answer.length > 0}
          <dl
            {...style(
              "bg-surface-subtle/50 rounded-control border border-border/70 divide-y divide-border/60",
            )}
          >
            {#each q.answer as [k, v], i (i)}
              <div
                {...style(
                  "grid px-3.5 py-2 gap-x-4 gap-y-0.5 sm:grid-cols-[minmax(8rem,10.5rem)_1fr] sm:items-baseline",
                )}
              >
                <dt {...style("text-muted text-xs font-medium")}>{k}</dt>
                <dd
                  {...style("min-w-0 text-foreground text-sm wrap-break-word whitespace-pre-wrap")}
                >
                  {v}
                </dd>
              </div>
            {/each}
          </dl>
        {:else}
          <p {...style("text-muted text-sm")}>
            The answer is confidential: only the question's responders can read it, until the asker
            has.
          </p>
        {/if}
      </Card>
    {/if}

    {#if item.can_answer && q.fields.length > 0}
      <section
        {...style("p-5 bg-surface rounded-panel border border-border-strong shadow-sm sm:p-6")}
      >
        <h2 {...style("text-foreground text-sm font-semibold")}>Your answer</h2>
        <p {...style("mt-1 mb-5 text-muted text-xs leading-relaxed")}>
          It goes to the asker, often an automated agent{q.confidential_question
            ? ""
            : ", and into the audit log"}. Never enter passwords, keys or other secrets.
          {#if item.needs_reauth}Answering needs a fresh sign-in; you will sign in again first.{/if}
        </p>

        {#if failure?.form === "answer"}
          <div {...style("mb-4")}><Banner>{failure.error}</Banner></div>
        {/if}

        <form
          method="POST"
          action="?/answer"
          use:enhance={answering.enhance}
          use:answering.keep={!q.confidential_question}
          {...style("flex flex-col gap-5")}
        >
          <input type="hidden" name="action" value="answer" />
          {#each q.fields as f (f.input)}
            {#if f.kind === "boolean" || f.kind === "choices"}
              <fieldset {...style("flex flex-col gap-2")}>
                <legend {...style("mb-1.5 text-foreground-secondary text-xs font-medium")}>
                  {f.label}{#if f.required}<span {...style("ml-1 font-normal text-muted")}
                      >(required)</span
                    >{/if}
                </legend>
                {#if f.description}
                  <p {...style("-mt-1 text-muted text-xs leading-relaxed")}>{f.description}</p>
                {/if}
                <div {...style("flex flex-wrap gap-2")}>
                  {#if f.kind === "boolean"}
                    {#each [["true", "Yes"], ["false", "No"]] as [value, text] (value)}
                      <label
                        {...style(
                          "flex h-9 px-3 items-center gap-2 text-sm bg-background rounded-control border border-border cursor-pointer hover:border-border-strong has-checked:bg-action-soft has-checked:border-action",
                        )}
                      >
                        <input
                          type="radio"
                          name={f.input}
                          {value}
                          checked={f.value === value}
                          {...style(check)}
                        />
                        {text}
                      </label>
                    {/each}
                  {:else}
                    {#each f.options as o (o.value)}
                      <label
                        {...style(
                          "flex h-9 px-3 items-center gap-2 text-sm bg-background rounded-control border border-border cursor-pointer hover:border-border-strong has-checked:bg-action-soft has-checked:border-action",
                        )}
                      >
                        <input
                          type="checkbox"
                          name={f.input}
                          value={o.value}
                          checked={o.selected}
                          {...style(check)}
                        />
                        {o.label}
                      </label>
                    {/each}
                  {/if}
                </div>
              </fieldset>
            {:else}
              <Field
                label={f.label}
                required={f.required}
                description={f.description}
                hint={f.hint}
              >
                {#if f.kind === "choice"}
                  <select name={f.input} {...style(control)}>
                    <option value="">—</option>
                    {#each f.options as o (o.value)}
                      <option value={o.value} selected={o.selected}>{o.label}</option>
                    {/each}
                  </select>
                {:else if f.kind === "number"}
                  <input
                    type="number"
                    name={f.input}
                    step={f.step}
                    min={f.min ?? undefined}
                    max={f.max ?? undefined}
                    value={f.value}
                    {...style(control, "tabular-nums")}
                  />
                {:else}
                  <input type={f.input_type} name={f.input} value={f.value} {...style(control)} />
                {/if}
              </Field>
            {/if}
          {/each}

          <label {...style("flex items-start gap-2.5")}>
            {#if q.confidential_question}
              <input type="checkbox" checked disabled {...style(check, "mt-0.5")} />
              <span>
                <span {...style("block text-foreground text-sm")}>This answer is confidential</span>
                <span {...style("block text-muted text-xs")}>
                  The answer to a confidential question is always confidential.
                </span>
              </span>
            {:else}
              <input
                type="checkbox"
                name="confidential"
                value="1"
                checked={q.answer_may_be}
                {...style(check, "mt-0.5")}
              />
              <span>
                <span {...style("block text-foreground text-sm")}>This answer is confidential</span>
                <span {...style("block text-muted text-xs")}>
                  A confidential answer is handed to the asker once and then removed; it is never
                  shown in chat.
                </span>
              </span>
            {/if}
          </label>

          <div>
            <Button size="lg" disabled={answering.busy}>
              <span aria-hidden="true" {...style("icon-md icon-lucide--send")}></span>
              {item.needs_reauth ? "Sign in again to answer" : "Send answer"}
            </Button>
          </div>
        </form>

        <details
          {...style("group mt-6 pt-5 border-border border-t")}
          open={failure?.form === "decline"}
        >
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
            <span aria-hidden="true" {...style("icon-sm icon-lucide--circle-slash")}></span>
            Decline to answer
          </summary>
          {#if failure?.form === "decline"}
            <div {...style("mt-3")}><Banner>{failure.error}</Banner></div>
          {/if}
          <form
            method="POST"
            action="?/decline"
            use:enhance={declining.enhance}
            use:declining.keep={!q.confidential_question}
            {...style("flex mt-3 flex-col gap-3 sm:flex-row sm:items-end")}
          >
            <input type="hidden" name="action" value="decline" />
            <div {...style("flex-1")}>
              <Field label="Note" hint="optional, goes to the asker">
                <input type="text" name="note" maxlength="500" {...style(control)} />
              </Field>
            </div>
            <Button variant="danger" disabled={declining.busy}>Decline</Button>
          </form>
        </details>
      </section>
    {:else if item.cannot_answer}
      <section
        {...style(
          "flex p-4 gap-2.5 text-muted text-sm bg-surface-subtle rounded-panel border border-border",
        )}
      >
        <span aria-hidden="true" {...style("icon-md icon-lucide--eye mt-0.5 shrink-0")}></span>
        <p {...style("leading-relaxed")}>{item.cannot_answer}</p>
      </section>
    {/if}
  </div>

  <aside {...style("p-5 bg-surface rounded-panel border border-border lg:sticky lg:top-20")}>
    <h2 {...style(heading)}>Details</h2>
    <dl {...style("divide-y divide-border/60")}>
      {#if outcome}
        <div {...style("py-2.5 first:pt-0 last:pb-0")}>
          <dt {...style(dt)}>Outcome</dt>
          <dd {...style(dd)}>
            {outcome.text}
            <span {...style("block text-muted text-xs")}><Time at={outcome.at} /></span>
          </dd>
        </div>
      {/if}
      {#if q.note}
        <div {...style("py-2.5 first:pt-0 last:pb-0")}>
          <dt {...style(dt)}>Note</dt>
          <dd {...style(dd)}>{q.note}</dd>
        </div>
      {/if}
      {#if q.pending_until}
        <div {...style("py-2.5 first:pt-0 last:pb-0")}>
          <dt {...style(dt)}>Answer by</dt>
          <dd {...style(dd)}>
            <Time at={q.pending_until} />
            <span {...style("block text-muted text-xs")}
              ><Time at={q.pending_until} mode="relative" /></span
            >
          </dd>
        </div>
      {/if}
      <div {...style("py-2.5 first:pt-0 last:pb-0")}>
        <dt {...style(dt)}>Asked</dt>
        <dd {...style(dd)}><Time at={q.created_at} /></dd>
      </div>
      <div {...style("py-2.5 first:pt-0 last:pb-0")}>
        <dt {...style(dt)}>Policy</dt>
        <dd {...style(dd)}><code {...style("font-mono text-xs")}>{q.policy}</code></dd>
      </div>
      <div {...style("py-2.5 first:pt-0 last:pb-0")}>
        <dt {...style(dt)}>Responders</dt>
        <dd {...style(dd)}>
          <span {...style("flex mt-1 flex-wrap gap-1")}>
            {#each q.responders as r (r)}
              <code
                {...style(
                  "px-1.5 py-0.5 font-mono text-xs bg-surface-subtle rounded border border-border/70",
                )}>{r}</code
              >
            {/each}
          </span>
        </dd>
      </div>
      <div {...style("py-2.5 first:pt-0 last:pb-0")}>
        <dt {...style(dt)}>Answering needs</dt>
        <dd {...style(dd)}><code {...style("font-mono text-xs")}>{q.min_assurance}</code></dd>
      </div>
    </dl>
  </aside>
</div>
