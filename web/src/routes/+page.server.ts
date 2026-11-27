import { read } from "#lib/server/ui.ts";
import type { Index } from "#lib/types.ts";

import type { PageServerLoad } from "./$types";

export const load = (async (event) => {
  event.depends("app:requests");
  return {
    index: await read<Index>(event, "/requests"),
  };
}) satisfies PageServerLoad;
