<script lang="ts">
  import { style } from "stillwind/svelte";
  import { onMount } from "svelte";

  type ThemeChoice = "system" | "light" | "dark";

  const STORAGE_KEY = "countersign:theme";

  const choices: { value: ThemeChoice; label: string }[] = [
    { value: "system", label: "System theme" },
    { value: "light", label: "Light theme" },
    { value: "dark", label: "Dark theme" },
  ];

  let active = $state<ThemeChoice>("system");

  onMount(() => {
    const t = document.documentElement.dataset.theme;
    active = t === "light" || t === "dark" ? t : "system";
  });

  function select(choice: ThemeChoice) {
    active = choice;
    if (choice === "system") {
      delete document.documentElement.dataset.theme;
      try {
        localStorage.removeItem(STORAGE_KEY);
      } catch {
        // Storage unavailable.
      }
    } else {
      document.documentElement.dataset.theme = choice;
      try {
        localStorage.setItem(STORAGE_KEY, choice);
      } catch {
        // Storage unavailable; theme still applies for this session.
      }
    }
  }

  const icon = style("icon-xs", {
    "data-[choice=system]:": "icon-lucide--monitor",
    "data-[choice=light]:": "icon-lucide--sun",
    "data-[choice=dark]:": "icon-lucide--moon",
  });
</script>

<div
  role="group"
  aria-label="Theme"
  {...style(
    "inline-flex p-0.5 items-center gap-0.5 bg-surface-subtle rounded-control border border-border",
  )}
>
  {#each choices as c (c.value)}
    <button
      type="button"
      data-theme-choice={c.value}
      aria-label={c.label}
      aria-pressed={active === c.value}
      title={c.label}
      onclick={() => select(c.value)}
      {...style(
        "flex size-6.5 items-center justify-center text-muted rounded-md transition-colors cursor-pointer",
        {
          "hover:": "text-foreground",
          "focus-visible:": "outline-2 outline-action outline-offset-1",
        },
      )}
    >
      <span aria-hidden="true" data-choice={c.value} {...style(icon)}></span>
    </button>
  {/each}
</div>
