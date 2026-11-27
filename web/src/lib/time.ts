// Times without Intl: the server code runs on QuickJS without locale data.

const pad = (n: number) => String(n).padStart(2, "0");

/** `2026-11-27 09:30 UTC`, or the browser's local time with `local`. */
export function formatTime(iso: string, local = false): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  if (local) {
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
}

/** `18:45` today, `11-28 18:45` on other days (UTC unless `local`). */
export function shortTime(iso: string, now: number, local = false): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  const n = new Date(now);
  const day = (x: Date) =>
    local ? [x.getMonth(), x.getDate()] : [x.getUTCMonth(), x.getUTCDate()];
  const [month = 0, date = 0] = day(d);
  const [nowMonth, nowDate] = day(n);
  const clock = local
    ? `${pad(d.getHours())}:${pad(d.getMinutes())}`
    : `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`;
  return month === nowMonth && date === nowDate ? clock : `${pad(month + 1)}-${pad(date)} ${clock}`;
}

/** `in 4 min`, `2 h ago`, `just now`. */
export function relative(iso: string, now: number): string {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) {
    return iso;
  }
  const diff = Math.round((t - now) / 1000);
  const abs = Math.abs(diff);
  if (abs < 45) {
    return "just now";
  }
  let words: string;
  if (abs < 3600) {
    words = `${Math.max(1, Math.round(abs / 60))} min`;
  } else if (abs < 86400) {
    words = `${Math.round(abs / 3600)} h`;
  } else {
    const days = Math.round(abs / 86400);
    words = `${days} ${days === 1 ? "day" : "days"}`;
  }
  return diff > 0 ? `in ${words}` : `${words} ago`;
}
