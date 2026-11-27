import { maybe, read } from "#lib/server/ui.ts";
import type { Me } from "#lib/types.ts";

import type { LayoutServerLoad } from "./$types";

export const load = (async (event) => {
  // Notices are shown to whoever arrives, signed in or not.
  if (event.route.id === "/notice") {
    return {
      me: await maybe<Me>("/me"),
    };
  }
  return {
    me: await read<Me>(event, "/me"),
  };
}) satisfies LayoutServerLoad;
