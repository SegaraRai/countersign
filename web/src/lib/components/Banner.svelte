<script lang="ts">
  import { style } from "stillwind/svelte";
  import type { Snippet } from "svelte";

  let {
    tone = "error",
    children,
  }: {
    tone?: "error" | "success" | "info" | "warning";
    children: Snippet;
  } = $props();
</script>

<div
  role={tone === "error" ? "alert" : "status"}
  data-tone={tone}
  {...style("flex px-3.5 py-2.5 items-start gap-2.5 text-sm rounded-control", {
    "data-[tone=error]:": "text-bad bg-bad-soft",
    "data-[tone=success]:": "text-good bg-good-soft",
    "data-[tone=info]:": "text-foreground-secondary bg-surface-subtle border border-border",
    "data-[tone=warning]:": "text-waiting bg-waiting-soft",
  })}
>
  <span
    aria-hidden="true"
    data-tone={tone}
    {...style("icon-md mt-0.5 shrink-0", {
      "data-[tone=error]:": "icon-lucide--circle-alert",
      "data-[tone=success]:": "icon-lucide--check",
      "data-[tone=info]:": "icon-lucide--info text-muted",
      "data-[tone=warning]:": "icon-lucide--triangle-alert",
    })}
  ></span>
  <div {...style("min-w-0 flex-1 leading-relaxed")}>{@render children()}</div>
</div>
