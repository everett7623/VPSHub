---
name: VPSHub
description: Security-first personal fleet ops panel — scannable ledger, gated actions
colors:
  accent: "#0f766e"
  accent-hover: "#0d5f59"
  accent-soft: "#d9efe9"
  bg: "#f3f5f2"
  bg-accent: "#e4ebe6"
  panel: "#ffffff"
  panel-soft: "#f8faf8"
  border: "#d5ddd7"
  border-strong: "#b8c4bc"
  text: "#1a2420"
  muted: "#5f6f67"
  danger: "#c24141"
  ok: "#1f8a5a"
  warn: "#b45309"
  on-accent: "#f4fffc"
typography:
  brand:
    fontFamily: "Source Serif 4, Georgia, serif"
    fontSize: "1.35rem"
    fontWeight: 600
    lineHeight: 1
    letterSpacing: "-0.03em"
  title:
    fontFamily: "Manrope, Segoe UI, sans-serif"
    fontSize: "1.25rem"
    fontWeight: 600
    lineHeight: 1.25
    letterSpacing: "-0.02em"
  body:
    fontFamily: "Manrope, Segoe UI, sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.45
  label:
    fontFamily: "Manrope, Segoe UI, sans-serif"
    fontSize: "0.78rem"
    fontWeight: 500
    letterSpacing: "0.02em"
  mono:
    fontFamily: "IBM Plex Mono, Consolas, Menlo, monospace"
    fontSize: "0.86em"
    fontWeight: 400
rounded:
  sm: "4px"
  badge: "5px"
  nav: "6px"
  control: "7px"
  md: "8px"
spacing:
  xs: "0.3rem"
  sm: "0.55rem"
  md: "0.85rem"
  lg: "1.25rem"
  xl: "1.35rem"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.on-accent}"
    rounded: "{rounded.control}"
    padding: "0.42rem 0.85rem"
    typography: "{typography.body}"
  button-primary-hover:
    backgroundColor: "{colors.accent-hover}"
    textColor: "{colors.on-accent}"
  button-secondary:
    backgroundColor: "transparent"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0.42rem 0.85rem"
  button-danger:
    backgroundColor: "{colors.danger}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    padding: "0.42rem 0.85rem"
  card:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.md}"
    padding: "1rem 1.15rem"
  input:
    backgroundColor: "{colors.panel}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "0.48rem 0.65rem"
  badge:
    backgroundColor: "{colors.panel-soft}"
    textColor: "{colors.muted}"
    rounded: "{rounded.badge}"
    padding: "0.12rem 0.42rem"
---

# Design System: VPSHub

## Overview

**Creative North Star: "The Fleet Ledger"**

VPSHub reads like an operator's fleet ledger: dense enough for tables and status matrices, calm enough for long sessions. Sage-tinted paper grounds the room; a single deep teal accent marks the next action. Brand moments use Source Serif 4; everything operational stays in Manrope so scan speed wins over decoration.

Atmosphere is tactile and confident without theatrics—controls feel pressable, borders do the structural work, and color is reserved for state (ok / warn / danger) and primary commits. Marketing flourish, purple-gradient chrome, and card-in-card nesting are out of character.

**Key Characteristics:**
- Ledger density: tables, badges, and stat grids over illustration
- One accent voice (teal) for commits and links
- Flat surfaces; depth from border + tonal wash only
- Serif brand mark, sans ops body, mono for codes/IDs
- Sticky frosted header as the persistent shell

## Colors

A cool sage paper field with one harbor teal accent and semantic status inks.

### Primary
- **Harbor Teal** (`#0f766e` / `{colors.accent}`): Primary buttons, links, focus ring tint, interactive hover targets. Hover deepens to **Harbor Teal Deep** (`#0d5f59`). Soft wash **Tide Mist** (`#d9efe9`) for nav hover and table row tint.

### Neutral
- **Sage Paper** (`#f3f5f2`): App canvas; fixed dual radial wash softens without competing.
- **Moss Wash** (`#e4ebe6`): Secondary canvas accent in the gradient field.
- **Ledger White** (`#ffffff`) / **Ledger Soft** (`#f8faf8`): Panels and badge/code fills.
- **Ink Grove** (`#1a2420`): Primary text.
- **Moss Mute** (`#5f6f67`): Labels, meta, inactive nav.
- **Fence Line** (`#d5ddd7`) / **Fence Strong** (`#b8c4bc`): Borders; strong for secondary button outline.

### Named status (not secondary brand)
- **Signal Red** (`#c24141`): Errors, danger actions, err badges.
- **Status Green** (`#1f8a5a`): Healthy / ok badges.
- **Amber Caution** (`#b45309`): Warnings and vault/maintenance banners.

**The One Accent Rule.** Harbor Teal is the only brand accent. Status greens/ambers/reds never double as decorative chrome; they only encode state.

## Typography

**Display Font:** Source Serif 4 (Georgia fallback) — shell brand + auth titles only  
**Body Font:** Manrope (Segoe UI fallback) — UI, tables, buttons  
**Label/Mono Font:** IBM Plex Mono (Consolas / Menlo) — `code`, IDs, hashes

**Character:** Serif announces the product name; sans runs the ledger. Tight negative tracking on titles keeps the console crisp at 15px base.

### Hierarchy
- **Brand** (600, ~1.35rem / auth ~1.85rem, lh 1): Product name and login heading only.
- **Title** (600, ~1.25rem, -0.02em): Page `h2` / section heads.
- **Body** (400, 15px, 1.45): Default copy and controls inherit.
- **Label** (500–550, ~0.76–0.8rem, uppercase + tracking on table/stat labels): Field labels, column headers, stat captions.
- **Mono** (0.86em): Inline code chips.

**The Brand-Only Serif Rule.** Source Serif 4 never appears in tables, badges, or form labels.

## Layout

Shell main max-width **72rem**, horizontal padding **~1.25rem**. Stat grid: 2 columns → 4 at `768px`. Tables are full-bleed inside cards; batch bars wrap with flex gaps (~0.55–0.85rem). Density favors ops scan: compact button padding, tight badge padding, sticky header.

## Elevation & Depth

Flat by default. Depth comes from 1px borders, soft tonal fills (`color-mix` with accent-soft / warn), and a frosted sticky header (`backdrop-filter: blur(10px)`), not drop shadows on cards.

**The Flat Ledger Rule.** No resting box-shadow on `.card`. The only intentional glow is the 3px focus ring on fields (`accent-soft` mix).

## Shapes

Gently curved controls, never pills: radius scale **4 / 5 / 6 / 7 / 8px** (code / badge / nav / control / card). Borders are hairline fence colors; badges use a light fill + matching status border.

## Components

### Buttons
Tactile and confident: solid teal primary, outlined secondary, solid danger.
- **Shape:** control radius (7px)
- **Primary:** Harbor Teal fill, on-accent text, padding `0.42rem 0.85rem`, weight 600
- **Hover / Focus:** deepen to accent-hover; disabled at 50% opacity
- **Secondary:** transparent + fence-strong border; soft panel fill on hover
- **Danger:** Signal Red fill for irreversible actions

### Cards / Containers
- **Corner Style:** 8px
- **Background:** near-opaque panel mix
- **Shadow Strategy:** none at rest (see Elevation)
- **Border:** Fence Line 1px
- **Internal Padding:** ~1–1.15rem

### Inputs / Fields
- **Style:** panel fill, fence border, 7px radius
- **Focus:** accent-tinted border + 3px Tide Mist ring
- **Label:** Moss Mute, ~0.8rem

### Badges
Compact status chips (5px radius); ok/warn/err tint text + border + 10% fill wash.

### Navigation
Sticky frosted header; muted text links with 6px hover wash; brand serif at left; actions cluster right.

### Tables
Uppercase muted headers; row hover with Tide Mist wash; body ~0.9rem.

### Banner
Warn-tinted panel for vault lock / attention; wraps with actions inline.

## Do's and Don'ts

### Do:
- **Do** keep Harbor Teal rare—primary commits and links only.
- **Do** encode health with Status Green / Amber Caution / Signal Red badges.
- **Do** prefer borders and tonal washes over shadows.
- **Do** use Source Serif 4 only for brand / auth title moments.
- **Do** preserve bilingual label length; keep UI density scannable.

### Don't:
- **Don't** introduce purple/indigo gradient themes or glow stacks.
- **Don't** nest cards inside cards for decoration.
- **Don't** use full-pill (`9999px`) controls.
- **Don't** turn status colors into large decorative fills.
- **Don't** put serif type in data tables or form labels.
