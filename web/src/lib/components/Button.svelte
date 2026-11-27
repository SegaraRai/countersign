<script lang="ts">
  import { style } from "stillwind/svelte";
  import type { Snippet } from "svelte";

  // Not `HTMLButtonAttributes`: the Stillwind compiler tries to resolve
  // `svelte/elements`, which only exports types.
  interface Props {
    variant?: "primary" | "secondary" | "ghost" | "approve" | "deny" | "danger";
    size?: "sm" | "md" | "lg";
    type?: "submit" | "button" | "reset";
    disabled?: boolean;
    name?: string;
    value?: string;
    formaction?: string;
    title?: string;
    "aria-label"?: string;
    "data-confirm"?: string;
    onclick?: (event: MouseEvent) => void;
    children: Snippet;
  }

  let { variant = "primary", size = "md", type = "submit", children, ...rest }: Props = $props();
</script>

<button
  {type}
  data-variant={variant}
  data-size={size}
  {...rest}
  {...style(
    "inline-flex items-center justify-center gap-1.5 font-medium whitespace-nowrap rounded-control border transition-colors cursor-pointer",
    {
      "data-[size=sm]:": "h-8 px-2.5 text-xs",
      "data-[size=md]:": "h-9 px-3.5 text-sm",
      "data-[size=lg]:": "h-10 px-4 text-sm font-semibold",
      "data-[variant=primary]:":
        "text-action-foreground bg-action border-transparent shadow-xs hover:bg-action-hover",
      "data-[variant=secondary]:":
        "text-foreground bg-surface-subtle border-border hover:bg-surface-hover hover:border-border-strong",
      "data-[variant=ghost]:":
        "text-foreground-secondary bg-transparent border-transparent hover:text-foreground hover:bg-surface-hover",
      "data-[variant=approve]:":
        "text-approve-foreground bg-approve border-transparent shadow-xs hover:bg-approve-hover",
      "data-[variant=deny]:":
        "text-bad bg-bad-soft border-bad/30 hover:text-deny-foreground hover:bg-deny hover:border-transparent",
      "data-[variant=danger]:":
        "text-bad bg-surface-subtle border-border hover:bg-bad-soft hover:border-bad/40",
      "focus-visible:": "outline-2 outline-action outline-offset-2",
      "disabled:": "opacity-50 pointer-events-none cursor-not-allowed",
    },
  )}
>
  {@render children()}
</button>
