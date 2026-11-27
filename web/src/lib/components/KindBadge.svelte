<script lang="ts">
  import { style } from "stillwind/svelte";

  let { kind }: { kind: "approval" | "question" } = $props();
</script>

<span
  data-kind={kind}
  {...style(
    "inline-flex h-5 px-1.5 items-center gap-1 text-[0.6875rem] font-medium tracking-wide uppercase rounded border",
    {
      "data-[kind=approval]:": "text-foreground-secondary bg-surface-subtle border-border",
      "data-[kind=question]:": "text-asking bg-asking-soft border-asking/20",
    },
  )}
>
  <span
    aria-hidden="true"
    data-kind={kind}
    {...style("icon-xs", {
      "data-[kind=approval]:": "icon-lucide--shield-check",
      "data-[kind=question]:": "icon-lucide--message-circle-question",
    })}
  ></span>
  {kind === "approval" ? "Approval" : "Question"}
</span>
