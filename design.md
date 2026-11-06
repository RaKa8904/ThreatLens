# ThreatLens Frontend Design & Architecture

## Overview
The ThreatLens frontend is a real-time, high-performance SOC dashboard designed for network security monitoring. Built with **React 18**, **TypeScript**, and **Vite**, it renders live passive telemetry, alerts on 6 specialized threat classes, and provides deep forensic dossiers.

## Technology Stack
- **Core:** React 18, TypeScript, Vite
- **Styling:** Tailwind CSS (utility-first styling with strict CSS variable design tokens)
- **Class Utilities:** `clsx`, `tailwind-merge`, `class-variance-authority`
- **Icons:** `hugeicons-react`
- **Data Visualization:** `recharts` for scalable charts
- **Build Tooling:** TypeScript compiler (`tsc`) & Vite for HMR and dead-code-eliminated production bundles
- **Motion:** `motion` (Framer Motion) for physics-based layout transitions and micro-interactions

---

## Design System & System Invariants

### 1. Color Palette Tokens & Contrast Guard
All background and surface tokens strictly use neutral Zinc tokens (`#09090b`, `#18181b`, `#27272a`). Arbitrary navy shades (`#070a14`, `#0d1222`, `#090d16`) are strictly forbidden.
- `--bg-base`: `#09090b` (Zinc 950)
- `--bg-surface`: `#18181b` (Zinc 900)
- `--bg-surface-hover`: `#27272a` (Zinc 800)
- `--hairline`: `#27272a` (Zinc 800)

**Typography Contrast Ratios (WCAG AA Compliant):**
- `--text-primary`: `#fafafa` (Zinc 50) — Contrast ~17:1 on `--bg-base`
- `--text-secondary`: `#a1a1aa` (Zinc 400) — Contrast ~5.3:1 on `--bg-base`
- `--text-muted`: `#8a8a94` — Contrast ~4.6:1 on `#09090b` and ~4.5:1 on `#18181b` (strictly meets 4.5:1 minimum)

**Role & Accent Colors:**
- **Analyst Role:** Sky Blue (`#38bdf8` / `text-sky-300`, `border-sky-500/30`)
- **Live / Streaming State:** Emerald (`#10b981` / `var(--live-accent)`) — Reserved exclusively for live telemetry and stream activity.
- **Admin Role:** Rose (`#f43f5e` / `text-rose-300`)

### 2. Severity Tokens (Single Source of Truth)
Defined centrally in `index.css`:
- `--severity-critical`: `#f43f5e` (Rose 500)
- `--severity-high`: `#f97316` (Orange 500)
- `--severity-moderate`: `#eab308` (Yellow 500)
- `--severity-low`: `#3b82f6` (Blue 500)

### 3. Type Scale
- `--text-display`: `2.5rem` (40px) / `font-bold` / `tracking-tight`
- `--text-heading`: `1.25rem` (20px) / `font-semibold` / `tracking-tight`
- `--text-body`: `0.875rem` (14px) / `font-normal`
- `--text-label`: `0.6875rem` (11px) / `uppercase` / `tracking-wider`
- `--text-mono`: `0.875rem` (14px) / `font-mono` / `tabular-nums`

---

## Accessibility & Motion Correctness

### 1. Motion Invariants (`useMotionEnabled`)
- **Default:** Strictly follows the OS `prefers-reduced-motion: reduce` media query.
- **URL Overrides:**
  - `?motion=on` forces motion animations ON.
  - `?motion=off` forces motion animations OFF.
- **Reduced Mode Behavior:**
  - No transforms (`translate`, `scale`, `rotate`).
  - Opacity fades clamped to at most 100ms.
  - No infinite looping animations; heartbeat dots become static, flow logs append without transition.
  - All Tailwind loop animations use the `motion-safe:` variant (e.g. `motion-safe:animate-pulse`, `motion-safe:animate-ping`, `motion-safe:animate-heartbeat`).

### 2. Stream Hover-Pause & Roving Focus
- **Hover & Focus Freeze:** Table freezing activates when:
  1. The cursor enters the threat table viewport.
  2. Any table row receives keyboard focus (`tabIndex={0}`).
  3. A row status dropdown is open.
  4. The Forensic Dossier drawer is open.
- **Pinned Pause Bar:** Displays a 32px top bar:
  `"{count} new alerts · Stream paused"` + `"Resume"` button.
  Includes a 300ms mouse leave debounce before unpausing.
- **Screen Reader Announcement:** A polite `aria-live="polite"` region notifies screen readers when the stream pauses or resumes.
- **Roving Keyboard Navigation:**
  - `ArrowUp` / `ArrowDown` navigate row-by-row.
  - `Enter` / `Space` opens the Forensic Dossier.
  - Active focused row features a 2px emerald focus ring (`focus:ring-2 focus:ring-emerald-500/80`).

---

## State Matrix & Dev State Switcher (`?state=`)
Gated by `import.meta.env.DEV` and tree-shaken from production builds via `src/lib/devState.ts`.

| Query Parameter | Behavior & Visual State |
| :--- | :--- |
| `?state=loading` | Forces the full-page layout skeleton (`DashboardSkeleton.tsx`). |
| `?state=empty` | Live buffer contains 0 alerts; displays initial waiting state. |
| `?state=filtered-empty` | Alerts are present, but active filter yields 0 matches. Displays contextual message (`"No {filter} alerts in the current {N}-alert buffer"`) and `"Clear filters"` button. |
| `?state=offline` | Mocks `status = "DISCONNECTED"`; displays offline status badge and inline warning banner. |
| `?state=stale` | Mocks stream stall (>5s without alerts); displays amber `STREAM IDLE` badge. |
| `?state=archive-error` | Forces database archive query failure branch; displays error recovery state. |
| `?state=session-expired` | Renders Login Page with the `"Session expired (401)"` alert notice. |

---

## Layout Skeletons & Degradation

### 1. Matching Skeleton Loader (`DashboardSkeleton.tsx`)
- Gated on a 300ms initial wait to eliminate layout flicker on fast connections.
- Matches exact production layout:
  - 4 hero metric cards with identical widths.
  - Throughput gauge and system vitals band.
  - Trends chart and incidents panel.
  - Table toolbar, header, and 8 rows at 44px height using identical grid columns:
    `grid-cols-[104px_minmax(300px,520px)_minmax(220px,380px)_104px_140px_124px_88px]`.

### 2. Connection Degradation
- When WebSocket disconnects (`status !== "CONNECTED"`):
  - Displays a slim inline warning band below Navbar:
    `"Connection lost. Showing data as of HH:MM:SS UTC. Reconnecting…"`
  - Passive client-side buffer remains interactive.

---

## Component Specifications

### 1. Incident Table & IP Suppression (`IncidentsPanel.tsx`)
- Displays correlated active incidents with start/end time spans and alert counts.
- **Direct IP Suppression:**
  - Each row features an inline `[SUPPRESS]` button (visible on hover and focus).
  - Clicking triggers an explicit confirmation modal before sending `POST /api/config/suppressions` (`rule_type: "source_ip"`).
  - Active suppression rules render a strikethrough on the IP with a `SUPPRESSED` badge.
  - Temporary feedback pill displays in the panel header on successful suppression.

### 2. Threat Table (`ThreatTable.tsx`)
- Grid alignment: Header and row share the identical template:
  `grid-cols-[104px_minmax(300px,520px)_minmax(220px,380px)_104px_140px_124px_88px]`.
- Row height: Fixed at 44px with a 2px left severity indicator bar.
- Fresh alert animation: Slide down with a live-accent flash over 900ms (motion-safe only).

### 3. Forensic Dossier Drawer (`ForensicDrawer.tsx`)
- Replaces heavy nested card borders with clean hairline dividers (`border-[var(--hairline)]`).
- **Copy-to-Clipboard:**
  - Direct 1-click copy buttons for Incident ID, Source IP, Destination IP, DNS queries, and JA3/JA4 cryptographic hashes.
  - Visual confirmation (`COPIED`) resets after 1.2s.
- **Unobserved Telemetry:**
  - Fields not observed for a given threat vector display `— Not observed` in muted italic text (`text-[var(--text-muted)]`), avoiding false-positive warning colors.
- **No Phantom Backend Actions:** Hex dump triggers and non-existent packet capture downloads are omitted; only verified backend telemetry is rendered.

### 4. Login Page (`LoginPage.tsx`)
- Asymmetric layout with passive telemetry aesthetics.
- Stripped of non-standard cyber artifacts (no radar sweeps, sonar rings, or scanning lines).
- Password visibility toggle (`ViewIcon` / `ViewOffSlashIcon`).
- CapsLock warning hint and inline error validation with `aria-describedby`.
- Session expiration notification banner.
