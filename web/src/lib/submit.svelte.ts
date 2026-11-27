import type { SubmitFunction } from "$app/forms";

const DRAFT_PREFIX = "countersign:draft:";

function draftKey(form: HTMLFormElement): string {
  return DRAFT_PREFIX + location.pathname + new URL(form.action).search;
}

/**
 * A form's submission state for `use:enhance`. Asks first when the clicked
 * button has `data-confirm`, keeps what was typed after a failure, and
 * leaves the app for sign-in, which countersignd serves itself. What was
 * typed survives that trip when the form also has `use:submission.keep`.
 */
export class Submission {
  busy = $state(false);

  enhance: SubmitFunction = ({ formElement, submitter, cancel }) => {
    const question = submitter instanceof HTMLElement ? submitter.dataset.confirm : undefined;
    if (question && !confirm(question)) {
      cancel();
      return;
    }
    this.busy = true;
    return async ({ result, update }) => {
      if (result.type === "redirect" && result.location.startsWith("/login")) {
        saveDraft(formElement);
        window.location.assign(result.location);
        return;
      }
      try {
        await update({ reset: false });
      } finally {
        this.busy = false;
      }
    };
  };

  /**
   * Restore what was typed before signing in again, once, and let it be
   * saved for that trip. Off for confidential content, which never goes to
   * browser storage.
   */
  keep = (form: HTMLFormElement, enabled = true) => {
    if (!enabled) {
      return;
    }
    form.dataset.keep = "";
    let saved: Record<string, string | string[]> | null = null;
    try {
      const key = draftKey(form);
      const raw = sessionStorage.getItem(key);
      sessionStorage.removeItem(key);
      saved = raw ? (JSON.parse(raw) as Record<string, string | string[]>) : null;
    } catch {
      return;
    }
    for (const [name, value] of Object.entries(saved ?? {})) {
      const field = form.elements.namedItem(name);
      if (
        field instanceof HTMLInputElement &&
        (field.type === "checkbox" || field.type === "radio")
      ) {
        field.checked = Array.isArray(value) ? value.includes(field.value) : field.value === value;
      } else if (field instanceof RadioNodeList) {
        const items = Array.from(field).filter(
          (el): el is HTMLInputElement => el instanceof HTMLInputElement,
        );
        if (items.length > 0 && items[0].type === "checkbox") {
          const selected = new Set(Array.isArray(value) ? value : [value]);
          for (const item of items) {
            item.checked = selected.has(item.value);
          }
        } else if (typeof value === "string") {
          field.value = value;
        }
      } else if (
        typeof value === "string" &&
        (field instanceof HTMLTextAreaElement ||
          field instanceof HTMLInputElement ||
          field instanceof HTMLSelectElement)
      ) {
        field.value = value;
      }
    }
  };
}

/** Typed text only: never what a button submitted, never hidden tokens. */
function saveDraft(form: HTMLFormElement) {
  const confidential = form.elements.namedItem("confidential");
  if (
    form.dataset.keep === undefined ||
    (confidential instanceof HTMLInputElement && confidential.checked)
  ) {
    return;
  }
  const draft: Record<string, string | string[]> = {};
  for (const el of form.elements) {
    if (
      (el instanceof HTMLTextAreaElement ||
        el instanceof HTMLSelectElement ||
        el instanceof HTMLInputElement) &&
      el.name &&
      el.type !== "hidden" &&
      el.type !== "submit" &&
      !((el.type === "checkbox" || el.type === "radio") && !(el as HTMLInputElement).checked)
    ) {
      const prev = draft[el.name];
      if (prev === undefined) {
        draft[el.name] = el.value;
      } else if (Array.isArray(prev)) {
        prev.push(el.value);
      } else {
        draft[el.name] = [prev, el.value];
      }
    }
  }
  try {
    sessionStorage.setItem(draftKey(form), JSON.stringify(draft));
  } catch {
    // Storage may be unavailable; the text is lost, as without this.
  }
}
