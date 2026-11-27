import { style } from "stillwind/svelte";

/** Text inputs, selects and textareas. */
export const control = style(
  "min-h-9 w-full min-w-0 px-3 py-1.5 text-foreground text-sm bg-code rounded-control border border-border transition-colors",
  {
    "placeholder:": "text-muted",
    "hover:": "border-border-strong",
    "focus-visible:": "bg-surface border-action outline-2 outline-action/25 outline-offset-0",
    "disabled:": "opacity-50 cursor-not-allowed",
  },
);

/** A small text input inside a table row. */
export const controlSm = style(
  "h-8 w-36 min-w-0 px-2.5 text-foreground text-xs bg-code rounded-control border border-border transition-colors",
  {
    "placeholder:": "text-muted",
    "hover:": "border-border-strong",
    "focus-visible:": "bg-surface border-action outline-2 outline-action/25 outline-offset-0",
  },
);

/** Native checkboxes and radio buttons. */
export const check = style(
  "size-4 shrink-0 cursor-pointer accent-action focus-visible:outline-2 focus-visible:outline-action focus-visible:outline-offset-2",
);

/** Section heading inside a page. */
export const heading = style(
  "mb-3 text-[0.6875rem] text-muted font-semibold tracking-[0.08em] uppercase",
);

/** Inline links inside text. */
export const link = style("text-action underline-offset-2 hover:underline");
