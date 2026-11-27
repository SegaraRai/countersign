import { act } from "#lib/server/ui.ts";
import type { LinkCode } from "#lib/types.ts";

import type { Actions } from "./$types";

export const actions: Actions = {
  default: (event) => act<LinkCode>(event, "link", "/link"),
};
