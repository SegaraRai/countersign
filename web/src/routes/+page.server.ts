import { read } from "#lib/server/ui.ts";
import type { Index } from "#lib/types.ts";

import type { PageServerLoad } from "./$types";

export const load = (async (event) => ({
  index: await read<Index>(event, "/requests"),
})) satisfies PageServerLoad;
