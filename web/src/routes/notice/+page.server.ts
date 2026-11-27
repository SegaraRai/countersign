import { error } from "@sveltejs/kit";

import { maybe } from "#lib/server/ui.ts";
import type { Notice } from "#lib/types.ts";

import type { PageServerLoad } from "./$types";

// countersignd renders this page itself, with what to say (sign-in
// problems, signing out); visited directly, there is nothing to show.
export const load = (async () => {
  const notice = await maybe<Notice>("/notice");
  if (!notice) {
    error(404, "Nothing to show.");
  }
  return { notice };
}) satisfies PageServerLoad;
