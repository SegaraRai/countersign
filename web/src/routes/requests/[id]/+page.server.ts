import { act, read } from "#lib/server/ui.ts";
import type { Item } from "#lib/types.ts";

import type { Actions, PageServerLoad } from "./$types";

const path = (id: string, rest = "") => `/requests/${encodeURIComponent(id)}${rest}`;

export const load = (async (event) => ({
  item: await read<Item>(event, path(event.params.id)),
})) satisfies PageServerLoad;

export const actions: Actions = {
  decide: (event) => act(event, "decide", path(event.params.id, "/decision")),
  revoke: (event) => act(event, "revoke", path(event.params.id, "/revoke")),
  // The forms say `action=answer` or `action=decline`.
  answer: (event) => act(event, "answer", path(event.params.id, "/answer")),
  decline: (event) => act(event, "decline", path(event.params.id, "/answer")),
};
