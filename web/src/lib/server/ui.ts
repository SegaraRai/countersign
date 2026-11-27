// The UI API, reached in process. countersignd attaches who is asking to
// every request the page makes here; nothing of that comes from this code.

import { error, fail, redirect, type RequestEvent } from "@sveltejs/kit";

const ORIGIN = "https://countersign.internal";

interface Problem {
  error: string;
  message: string;
  login?: string;
}

async function problem(res: Response): Promise<Problem> {
  try {
    return (await res.json()) as Problem;
  } catch {
    return { error: "unknown", message: `Unexpected response (${res.status}).` };
  }
}

/** Where to sign in and come back to `url`. */
export function loginUrl(url: URL): string {
  return `/login?next=${encodeURIComponent(url.pathname + url.search)}`;
}

/** GET `path`: its JSON, or the page's error (signed out: off to sign in). */
export async function read<T>(event: Pick<RequestEvent, "url">, path: string): Promise<T> {
  const res = await fetch(ORIGIN + path);
  if (res.ok) {
    return (await res.json()) as T;
  }
  const p = await problem(res);
  if (res.status === 401) {
    redirect(303, loginUrl(event.url));
  }
  error(res.status, p.message);
}

/** GET `path`, or null when it is not there or not for this reader. */
export async function maybe<T>(path: string): Promise<T | null> {
  const res = await fetch(ORIGIN + path);
  return res.ok ? ((await res.json()) as T) : null;
}

/**
 * POST the form of the action named `form` to `path`. Returns the API's
 * JSON, or a failure the page shows next to that form. A change that needs
 * a fresh sign-in sends the browser to sign in again.
 */
export async function act<T = { ok: true }>(
  event: Pick<RequestEvent, "url" | "request">,
  form: string,
  path: string,
) {
  const params = new URLSearchParams();
  for (const [k, v] of (await event.request.formData()).entries()) {
    if (typeof v === "string") {
      params.append(k, v);
    }
  }
  const res = await fetch(ORIGIN + path, { method: "POST", body: params });
  if (res.ok) {
    return { form, done: (await res.json()) as T };
  }
  const p = await problem(res);
  if (p.error === "fresh_auth_required" && p.login) {
    redirect(303, p.login);
  }
  if (p.error === "unauthenticated") {
    redirect(303, loginUrl(event.url));
  }
  return fail(res.status, { form, error: p.message });
}
