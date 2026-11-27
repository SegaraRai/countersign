import { act, read } from "#lib/server/ui.ts";
import type { AdminPage } from "#lib/types.ts";

import type { Actions, PageServerLoad } from "./$types";

export const load = (async (event) => ({
  admin: await read<AdminPage>(event, "/admin"),
})) satisfies PageServerLoad;

export const actions: Actions = {
  // The form says what: suspend, reinstate, revoke-approved-by, unlink.
  default: (event) => act(event, "admin", "/admin/action"),
};
