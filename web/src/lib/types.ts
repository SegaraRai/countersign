// What the UI API (countersignd's `web/ui.rs`) returns.

export type Tone = "waiting" | "asking" | "good" | "done" | "bad" | "muted";
export type Assurance = "linked" | "web" | "fresh-auth";

export interface Detail {
  label: string;
  value: string;
}

export interface When {
  label: string;
  at: string;
}

export interface Me {
  person: string;
  name: string;
  roles: string[];
  member: boolean;
  oversees: boolean;
  admin: boolean;
  csrf: string;
  assurance: Assurance;
  fresh_until: string | null;
}

export interface Row {
  kind: "approval" | "question";
  id: string;
  headline: string;
  summary?: string;
  label: string;
  tone: Tone;
  time?: When;
  created_at: string;
  updated_at: string;
}

export interface Index {
  /** Someone has to decide or answer. */
  waiting: Row[];
  /** Approved and not over yet. */
  active: Row[];
  recent: Row[];
}

export type Shown =
  | {
      type: "command";
      line: string;
    }
  | {
      type: "lines";
      title: string;
      lines: Detail[];
    }
  | {
      type: "question";
      message: string;
      fields: Detail[];
    };

export interface DecisionLine {
  who: string;
  approved: boolean;
  via: string;
  assurance: Assurance;
  at: string;
  comment?: string;
}

export interface UseLine {
  at: string;
  what: string;
}

export interface Status {
  state: string;
  label: string;
  detail?: string;
  time?: When;
  needs?: string;
  tone: Tone;
  decisions?: DecisionLine[];
  uses?: UseLine[];
}

export interface Presentation {
  kind: "approval" | "question";
  headline: string;
  withheld: boolean;
  grant: string;
  action?: Shown;
  facts: Detail[];
  claims?: Detail[];
  notes?: string[];
  status: Status;
  audit?: Detail[];
}

export interface ApprovalPage {
  kind: "approval";
  id: string;
  p: Presentation;
  claims_note: string;
  sensitive: boolean;
  can_decide: boolean;
  can_revoke: boolean;
  approve_needs_reauth: boolean;
  fresh_until: string | null;
  cannot_decide: string | null;
}

export interface OptionView {
  value: string;
  label: string;
  selected: boolean;
}

export interface FieldView {
  input: string;
  label: string;
  description: string | null;
  required: boolean;
  kind: "text" | "number" | "boolean" | "choice" | "choices";
  input_type: string;
  step: string;
  min: number | null;
  max: number | null;
  value: string;
  hint: string | null;
  options: OptionView[];
}

export type Outcome =
  | {
      kind: "answered" | "declined";
      by: string;
      via: string;
      assurance: string;
      at: string;
    }
  | { kind: "expired" | "withdrawn"; at: string };

export interface QuestionView {
  asker: string;
  asker_actor: string | null;
  policy: string;
  message: string | null;
  context: [string, string][];
  confidential_question: boolean;
  answer_may_be: boolean;
  removed: boolean;
  created_at: string;
  pending_until: string | null;
  responders: string[];
  min_assurance: string;
  outcome: Outcome | null;
  answer_confidential: boolean;
  answer: [string, string][];
  answer_hidden: boolean;
  note: string | null;
  fields: FieldView[];
}

export interface QuestionPage {
  kind: "question";
  id: string;
  headline: string;
  status: {
    label: string;
    tone: Tone;
    detail?: string;
    time?: When;
  };
  grant: string;
  q: QuestionView;
  can_answer: boolean;
  needs_reauth: boolean;
  read_needs_reauth: boolean;
  cannot_answer: string | null;
}

export type Item = ApprovalPage | QuestionPage;

export interface ActorView {
  id: string;
  kind: "person" | "workload";
  name: string;
  active: boolean;
  suspension: { by: string; since: string; reason: string | null } | null;
  groups: string[];
  roles: string[];
  owners: string[];
}

export interface AdminPage {
  admin: boolean;
  actors: ActorView[];
  links: {
    channel: string;
    external_id: string;
    person: string;
    linked_at: string;
  }[];
  actions: {
    at: string;
    by: string;
    action: string;
    target: string;
    detail: string | null;
  }[];
}

export interface LinkCode {
  code: string;
  expires: string;
}

export interface Notice {
  heading: string;
  body: string;
  detail?: string;
}
