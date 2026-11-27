<script lang="ts">
  import { style } from "stillwind/svelte";
  import { onMount } from "svelte";

  import Banner from "#lib/components/Banner.svelte";
  import Button from "#lib/components/Button.svelte";
  import Time from "#lib/components/Time.svelte";

  interface SubscriptionSummary {
    id: string;
    label?: string;
    created_at: string;
  }

  interface PushConfig {
    enabled: boolean;
    vapid_public_key?: string;
    subscriptions: SubscriptionSummary[];
  }

  let { csrf }: { csrf: string } = $props();

  let config = $state<PushConfig | null>(null);
  let supported = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);

  function base64UrlToUint8Array(base64Url: string): Uint8Array<ArrayBuffer> {
    const padding = "=".repeat((4 - (base64Url.length % 4)) % 4);
    const base64 = (base64Url + padding).replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(base64);
    const buffer = new ArrayBuffer(raw.length);
    const output = new Uint8Array(buffer);
    for (let i = 0; i < raw.length; i += 1) {
      output[i] = raw.charCodeAt(i);
    }
    return output;
  }

  function deviceLabel(): string {
    const ua = navigator.userAgent;
    if (ua.includes("Firefox")) {
      return "Firefox";
    }
    if (ua.includes("Edg/")) {
      return "Edge";
    }
    if (ua.includes("Chrome")) {
      return "Chrome";
    }
    if (ua.includes("Safari")) {
      return "Safari";
    }
    return "Browser";
  }

  async function refresh() {
    try {
      const res = await fetch("/api/push/config", { credentials: "same-origin" });
      if (!res.ok) {
        return;
      }
      config = (await res.json()) as PushConfig;
    } catch {
      // Ignore network errors while loading optional push state.
    }
  }

  async function enable() {
    if (!config?.vapid_public_key) {
      return;
    }
    busy = true;
    error = null;
    notice = null;
    try {
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        error = "Browser notification permission was not granted.";
        return;
      }
      const reg = await navigator.serviceWorker.register("/sw.js");
      await navigator.serviceWorker.ready;
      const existing = await reg.pushManager.getSubscription();
      const sub =
        existing ??
        (await reg.pushManager.subscribe({
          userVisibleOnly: true,
          applicationServerKey: base64UrlToUint8Array(config.vapid_public_key),
        }));
      const json = sub.toJSON();
      if (!json.endpoint || !json.keys?.p256dh || !json.keys?.auth) {
        error = "Browser returned an incomplete push subscription.";
        return;
      }
      const res = await fetch("/api/push/subscriptions", {
        method: "POST",
        credentials: "same-origin",
        headers: {
          "content-type": "application/json",
          "x-csrf-token": csrf,
        },
        body: JSON.stringify({
          endpoint: json.endpoint,
          keys: {
            p256dh: json.keys.p256dh,
            auth: json.keys.auth,
          },
          label: deviceLabel(),
        }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => null)) as { message?: string } | null;
        error = body?.message ?? "Could not save push subscription.";
        return;
      }
      notice = "Notifications enabled on this device.";
      await refresh();
    } catch (e) {
      error = e instanceof Error ? e.message : "Could not enable browser notifications.";
    } finally {
      busy = false;
    }
  }

  async function remove(id: string) {
    busy = true;
    error = null;
    notice = null;
    try {
      const res = await fetch(`/api/push/subscriptions/${encodeURIComponent(id)}`, {
        method: "DELETE",
        credentials: "same-origin",
        headers: {
          "x-csrf-token": csrf,
        },
      });
      if (!res.ok) {
        error = "Could not remove subscription.";
        return;
      }
      await refresh();
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    supported =
      typeof window !== "undefined" &&
      "serviceWorker" in navigator &&
      "PushManager" in window &&
      "Notification" in window;
    void refresh();
  });
</script>

{#if config?.enabled}
  <section {...style("flex mt-8 p-6 flex-col gap-4 bg-surface rounded-panel border border-border")}>
    <div {...style("flex flex-wrap items-start justify-between gap-4")}>
      <div>
        <h2 {...style("text-base text-foreground font-semibold")}>Browser push notifications</h2>
        <p {...style("mt-1 text-foreground-secondary text-sm leading-relaxed")}>
          Receive alerts on this device only for requests and questions you are eligible to decide.
        </p>
      </div>
      {#if supported}
        <Button variant="primary" type="button" disabled={busy} onclick={enable}>
          {busy ? "Working…" : "Enable on this device"}
        </Button>
      {/if}
    </div>

    {#if !supported}
      <p {...style("text-muted text-xs leading-relaxed")}>
        This browser does not expose Web Push here (on iOS, add Countersign to your Home Screen
        first).
      </p>
    {/if}

    {#if error}
      <Banner>{error}</Banner>
    {/if}
    {#if notice}
      <p {...style("text-good text-sm font-medium")}>{notice}</p>
    {/if}

    {#if config.subscriptions.length > 0}
      <ul {...style("border-border border-t divide-y divide-border")}>
        {#each config.subscriptions as sub (sub.id)}
          <li {...style("flex py-3 items-center justify-between gap-4")}>
            <div {...style("min-w-0")}>
              <p {...style("text-foreground text-sm font-medium")}>
                {sub.label ?? "Subscribed browser"}
              </p>
              <p {...style("text-muted text-xs")}>
                Added <Time at={sub.created_at} mode="relative" />
              </p>
            </div>
            <Button variant="ghost" type="button" disabled={busy} onclick={() => remove(sub.id)}>
              Remove
            </Button>
          </li>
        {/each}
      </ul>
    {/if}
  </section>
{/if}
