import { invalidate, invalidateAll } from "$app/navigation";
import { onMount } from "svelte";

/**
 * Reload the page's data every `seconds` while the tab is visible, and when
 * it becomes visible again, so waiting requests show up without a reload.
 * Pass a dependency key (e.g. `"app:requests"`) to avoid re-fetching layout `/me`.
 */
export function refreshEvery(seconds: number, dep?: string) {
  onMount(() => {
    const tick = () => {
      if (document.visibilityState === "visible") {
        void (dep ? invalidate(dep) : invalidateAll());
      }
    };
    const timer = setInterval(tick, seconds * 1000);
    document.addEventListener("visibilitychange", tick);
    return () => {
      clearInterval(timer);
      document.removeEventListener("visibilitychange", tick);
    };
  });
}
