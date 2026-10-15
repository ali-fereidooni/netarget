# Design system: netarget panel

Modelled on the ParsPack client panel. Tokens live in `web/static/style.css` (`:root` = dark,
`[data-theme=light]` = light). Everything references tokens.

## Color (dark default)

| Role | Dark | Light | Use |
|---|---|---|---|
| `--bg` | `#05080D` | `#E9EDF7` | page |
| `--rail` | `#0A101A` | `#FFFFFF` | sidebar, top bar (second neutral layer) |
| `--panel` | `#0E1622` | `#F5F8FE` | widgets |
| `--panel-2` | `#132033` | `#E3EAF6` | inset rows, inputs, code |
| `--ink` | `#C8D1E0` | `#3D505C` | body text |
| `--ink-strong` | `#F1F5FB` | `#0A101A` | headings, values |
| `--muted` | `#7A98AD` | `#5E7685` | secondary |
| `--primary` | `#3288E5` | `#2A78CC` | primary action, selection, focus, links |
| `--on-primary` | `#020D13` | `#FFFFFF` | text on primary |
| `--ok` | `#31C1B0` | `#118C7E` | OK |
| `--warn` | `#FCAA67` | `#B55E12` | WARN |
| `--fail` | `#F0607F` | `#C22F4F` | FAIL |

Status color appears only on state (pills, pipeline, finding markers), never as decoration.

## Type

Vazirmatn variable (self-hosted, Latin + Persian), one family. Fixed rem scale ≈1.2:
12 / 13 / 14 (body) / 16 / 20 / 24. Weights 400/500/700. Tabular numerals in tables and timings.
Monospace only for record values, evidence and raw JSON (data, not costume).

## Shape and depth

Radius: controls 12px, buttons 15px (ParsPack), widgets 20px, pills full. Depth by tone steps
(bg → rail → panel → panel-2); shadows only with offset and blur (`0 10px 30px -18px`), never
glows or hard offsets. No borders between surfaces except data tables and inputs.

## Layout

App shell: sidebar on the inline-start side (left in LTR, right in RTL) with brand, navigation,
language and theme switches; content column max 1120px. Logical CSS properties throughout so RTL is
a `dir` flip. Below 900px the sidebar becomes a top bar.

## Signature

The **pipeline rail**: five connected steps (registration → web) that light up as SSE events arrive
and end in the diagnosis colour. It is the one authored motion moment (200ms state transitions,
reduced-motion safe). Everything else is still.

## i18n

UI strings in `app.js` (`STRINGS.en` / `STRINGS.fa`). Backend text is rendered with `dir="auto"`.
