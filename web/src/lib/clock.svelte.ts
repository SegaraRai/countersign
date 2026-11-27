import { onMount } from "svelte";

const state = $state({ now: 0, local: false });
let users = 0;
let timer: ReturnType<typeof setInterval> | undefined;

/**
 * The current time for relative times, ticking every 15 s in the browser,
 * and whether the page runs there: times switch to the local zone after
 * hydration. During server rendering `now` is the time of the render.
 */
export function useClock() {
  onMount(() => {
    users += 1;
    if (users === 1) {
      state.local = true;
      state.now = Date.now();
      timer = setInterval(() => {
        state.now = Date.now();
      }, 15_000);
    }
    return () => {
      users -= 1;
      if (users === 0) {
        clearInterval(timer);
      }
    };
  });
  return {
    get now() {
      return state.local ? state.now : Date.now();
    },
    get local() {
      return state.local;
    },
  };
}
