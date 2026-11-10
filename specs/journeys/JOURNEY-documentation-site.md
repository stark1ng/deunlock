# JOURNEY-documentation-site: Learn the authentication mechanics

## Roadmap Link

- Source scope: the user's documentation request, separate from product roadmap work.
- Design context: [deunlock specification](../deunlock/SPEC.md) and [presence architecture](../unlock-proximity/SPEC.md).
- Feature: browsable documentation with branded, accessible animated explanations.
- Outline: `.agents/instructions/instr-journey.md` is absent; this document follows the full outline in `.agents/skills/journey/SKILL.md`.

## 1. Journey

When evaluating or operating deunlock, I want to follow pairing, discovery, and a phone-approved unlock so I understand what authorizes access and where failures occur.

## 2. CJM

The reader arrives from the repository, chooses a tutorial or explanation, then follows the actual source behavior. The original cat paw and key connect the documentation to the Android application. Animations supplement the numbered prose.

### Phase 1: Find the right page

**User Intent:** Identify prerequisites and a suitable reading path.

**Actions:** Open the landing page, choose a tutorial, or search for a term.

**Pain / Risk:** Navigation may hide the tutorial; an external font may fail; mobile content may overflow.

**Success Signal:** The landing page, search, and navigation work locally without external asset requests.

### Phase 2: Understand the exchange

**User Intent:** See which actor sends each message and which action authorizes access.

**Actions:** Open the mechanics page; play, pause, step, and restart each explanation.

**Pain / Risk:** Movement may be uncomfortable; diagrams may imply passive unlock; diagrams may claim stronger cryptography than the implementation provides.

**Success Signal:** All steps have named actors and readable descriptions; fresh approval and biometrics remain explicit; reduced motion disables packet movement.

### Phase 3: Read and contribute reliably

**User Intent:** Read the complete account, then reproduce the documentation checks.

**Actions:** Disable JavaScript or print the page; build the site; run the browser check.

**Pain / Risk:** Essential content may depend on scripts; links may break; dependencies may drift; CI may publish without approval.

**Success Signal:** Numbered prose survives without JavaScript, the strict build and browser checks pass, and CI only produces an artifact.

### Friction and Opportunity

| Friction | Phase | Opportunity |
| --- | --- | --- |
| Missing reading paths | Find | Diátaxis navigation and search |
| Invisible protocol boundaries | Understand | Actor labels, packet motion, explicit consent |
| Animation discomfort | Understand | Paused default, native controls, reduced motion |
| Difficult reproduction | Contribute | Pinned dependencies and a single check command |

### North Star Summary

A reader can describe pairing, discovery, approval, signature verification, and PAM policy in order, using either the illustrations or the complete prose. The documentation does not change authentication behavior.

## Stressors and resilience

| Stressor | Response |
| --- | --- |
| JavaScript disabled | Complete adjacent prose; hide empty mounts |
| Reduced-motion preference | Default pause and disable all packet movement |
| Preference changes while playing | Pause and refresh the motion note |
| Hidden browser tab | Pause progression |
| Keyboard-only input | Native buttons and visible focus |
| Narrow phone viewport | Wrapping controls and responsive actor cards |
| Very long labels | Actor text wraps inside its cell |
| Search worker startup | Browser test waits for actual search results |
| Broken internal links | Strict MkDocs build plus local link traversal |
| External fonts unavailable | System font stack; no font CDN |
| Dependency release drift | Fully pinned requirements |
| Production configuration changes | Source-linked prose and isolated flow data |
| Repeated initialization | Existing widget children prevent duplicate mounting |
| Interrupted playback | Explicit pause/restart and visible current step |
| Unapproved publishing | Read-only workflow permissions and artifact upload only |

## 3. UX Implementation and Assessment

### Time to First Value

- The landing page exposes the tutorial and mechanics without opening a menu.

### Onboarding Clarity

- Tutorial, how-to, reference, and explanation have distinct navigation groups.

### Production-Ready Defaults

- Illustrations start paused and perform no authentication or network requests.

### Golden Path Quality

- Each flow reaches its final step and can restart from its first step.

### Decision Load

- Controls use Play/Pause, Next step, and Restart.

### Progressive Complexity

- Readers choose a visual explanation or continue with the numbered transcript.

### Error Quality

- Strict build output identifies broken documentation references.

### Failure Safety

- Missing JavaScript preserves essential documentation.

### Runtime Transparency

- Current step, active actors, and playback state are visible.

### Debuggability

- Flow data lives in one JavaScript file with source behavior explained in the adjacent prose.

### Cross-Surface Consistency

- The app's black, white, dim, border, success, warning, and danger colors define the site palette; the repository's cat paw and key remain the mascot.

### Workflow Consistency

- Authors use MkDocs and Markdown, following the existing codefang documentation convention requested by the user.

### Change Safety

- New canonical pages coexist with the legacy flat documents; build exclusions avoid publishing conflicting accounts.

### Experimentation Safety

- The local preview affects no PAM configuration, Bluetooth device, or deployment.

### Interaction Latency

- Next step and Restart update synchronously; playback is explicitly initiated.

### Developer Feedback Speed

- A single checker builds, serves on an ephemeral loopback port, and exercises the browser.

### Team Scale

- CI and local builds consume the same pinned dependency file.

### System Scale

- New pages use the existing navigation and theme; flow mounts share one component.

### Right Behavior by Default

- Paused animations, local assets, and keyboard access need no reader configuration.

### Anti-Bypass Design

- CI requires a strict build and browser checks before producing a site artifact.

## 4. Tests

### TC-01: Build a browsable site

**Given** pinned dependencies and the Markdown tree.
**When** the checker builds with `--strict`.
**Then** the build succeeds and every local HTML link resolves.

### TC-02: Read every exchange

**Given** the mechanics page in a real browser.
**When** the reader advances each widget through its steps.
**Then** each explanation reaches its named final stage and disables further advance.

### TC-03: Control motion

**Given** paused animations.
**When** the reader plays, pauses, advances, and restarts.
**Then** playback advances, pause remains stable, and restart returns to the first step.

### TC-04: Use a keyboard

**Given** a focused Next step or Restart button.
**When** the reader presses Enter or Space.
**Then** the corresponding action updates the visible step.

### TC-05: Respect reduced motion

**Given** a browser reporting reduced motion.
**When** the reader opens an explanation or starts playback.
**Then** packet movement stays disabled and the reduced-motion note is visible.

### TC-06: Read without JavaScript

**Given** a browser with scripts disabled.
**When** the reader opens the mechanics page.
**Then** explanatory prose remains visible and empty widget mounts are hidden.

### TC-07: Read on a phone

**Given** a narrow mobile viewport.
**When** the reader opens the landing and mechanics pages.
**Then** the document has no horizontal overflow and controls remain usable.

### TC-08: Find an explanation

**Given** the built site and its local search index.
**When** the reader searches for a documented protocol term.
**Then** search offers a result within the site.

## Traceability

- Product design references: the two specifications linked above; no product roadmap rows are closed by this documentation task.
- Test file: `scripts/docs-check.py`.

## Implementation

- `mkdocs.yml`: strict site configuration, navigation, local fonts, legacy page exclusions.
- `requirements-docs.in` and `requirements-docs.txt`: pinned direct inputs and resolved dependencies.
- `assets/deunlock.png`, `docs/assets/deunlock.png`, and the Android launcher foreground: matching copies of the regenerated paw logo, retaining the composition while correcting the central paw anatomy.
- `assets/deunlock-logo.prompt.txt`: the exact prompt used with the built-in image generation tool.
- `docs/stylesheets/deunlock.css`: application palette, sampled mascot accents, responsive layout, 44-pixel touch controls, print colors, and motion preferences.
- `docs/javascripts/mechanics.js`: pairing, discovery, and unlock controls.
- `scripts/docs-check.py`: local build, link validation, and browser journeys.
- `.github/workflows/docs.yml`: build/check workflow with an uploaded artifact and no deployment.

Source format attribution: the repository's `.agents/skills/journey/SKILL.md` journey outline.

## Validation evidence

- `node --check docs/javascripts/mechanics.js` passes.
- `python -m py_compile scripts/docs-check.py` passes.
- Matching hashes confirm the root logo, documentation artwork, and Android launcher foreground use the same corrected mascot.
- The browser checker builds the site strictly and validates all local links and anchors across 13 HTML pages.
- Pairing, discovery, and unlock complete in 7, 6, and 7 readable steps; completion disables further advance and Restart returns to the first step.
- Browser checks cover playback, pause stability, keyboard actions, changed and initial reduced motion, local search, script-free transcripts, desktop/mobile overflow, 44-pixel touch targets, and text contrast in screen and print media.
- The checker blocks external asset requests. A test caught Material's automatic GitHub statistics requests; a static footer repository link replaced that widget.
- Browser automation reports every tab as visible even after tab switching or window minimization. Hidden-document pause is therefore checked with a **simulated visibility getter/event**, exercising the real component listener and timer. No real tab-hide transition is claimed.
- Browser screenshots are emitted under ignored `target/docs-preview/`: `desktop-home.png`, `desktop-mechanics.png`, `mobile-home.png`, and `mobile-mechanics.png`.
- The parent agent ran `make lint` and `make test`: lint passed; 447 Rust tests passed and 9 were ignored. No Rust source changed in this documentation task.

## Logo anatomy correction

Final pre-PR validation passed with the project owner's artwork: the complete documentation browser checker, `make lint`, and `make test` (447 passed, 9 ignored). The browser checker now waits for the desktop landscape layout before recording its baseline; see [BUG-20261020-0252](../bugs/BUG-20261020-0252.md) for the reproduced resize-observer race and verification.

The project owner subsequently refined `assets/deunlock.png` manually. That file is the authoritative final artwork and has been copied unchanged to the documentation and Android foreground assets. The prompt file distinguishes the generated base from these manual refinements. The strict documentation build passes with the owner's image, and the built site contains the same PNG bytes.

The user requested a close regeneration of the existing logo and clarified that the key must cross the front of the paw, held by a connected fifth digit. The selected edit keeps the four raised toes and their pink pads, central pink paw pad, upright white foreleg, horizontal gold key, black background, and composition. Following the user's proportion feedback, a broader fifth digit curls inward over the shaft from a continuous attachment at the paw's right edge. Its small, straight ivory claw follows the gripping finger's own diagonal axis and uses coarse square pixel steps. The selected image replaces the root logo and both consuming copies. The exact built-in image generation prompt is retained at `assets/deunlock-logo.prompt.txt`.

- The root, documentation, and Android foreground files have matching SHA-256 hashes.
- Before the fifth-digit grip correction, Android `:app:assembleDebug --offline` passed, and a pixel comparison confirmed that earlier image was packaged in the debug APK.
- The latest Android rebuild cannot locate the SDK configured at `/home/dmitriy/sources/prrr/android-sdk`; that directory is absent. The new foreground asset is synchronized, but the existing APK does not verify this latest image.
- The full browser checker passed with the earlier regenerated artwork, including all 20 illustrated chapters, motion controls, mobile/tablet layouts, local assets, and print output. For the corrected grip, the strict site build and a browser check confirm the new PNG loads and matches the source bytes.

## Illustrated mechanics acceptance

The user clarified that the diagrams need the visual depth of an illustrated system-design explainer: drawn devices, trust boundaries, message routes, packet fields, a Keystore key, and a biometric fingerprint. Three cards and a moving square do not satisfy this requirement.

The accepted diagram contract keeps source behavior and readable transcripts, and adds:

- Drawn terminal, daemon, and phone actors for unlock; desktop and phone for pairing and discovery.
- Labeled, progressive message routes and an envelope that moves between actors during playback.
- Visible nonce and MAC fields on the challenge, the signature width on the response, and distinct signature-valid and nonce-unseen verification results.
- The private Keystore key drawn inside the phone during signing; approval and strong-biometric illustrations precede the signature.
- Matching numeric-comparison values on both pairing devices; host-public-key read before phone-public-key write; an explicit public-input derivation caveat.
- UUID matching and CCCD subscription readiness for discovery.
- Direct chapter navigation, Previous step, native playback-speed selection, stable keyboard focus, and paused defaults.
- A portrait scene layout on narrow widgets, readable labels, 44-pixel touch controls, complete non-script transcripts, reduced-motion behavior, and readable print output.

### Red evidence

`scripts/docs-check.py` was extended before the illustrated implementation. It failed with `Locator expected to be visible; Actual value: None` for `.sy-mechanics[data-flow="unlock"] svg.sy-scene[role=img]`. The ignored diagnostic log is `target/docs-preview/rich-diagram-red.log`. This failure demonstrates that the previous cards do not meet the new illustration contract.

### Additional browser acceptance

The browser checker inspects visible diagram labels and state, chapter seeking/back/reset, preserved focus, matching pairing codes, key containment, and packet geometry. It samples actual packet positions while playing and paused, then checks both CSS/Web Animations and requestAnimationFrame movement under reduced motion. Mobile checks inspect portrait view boxes, label dimensions and clipping, touch targets, and overflow. Screenshots include approval, verification, pairing comparison, and discovery subscription stages on desktop and mobile.

### Illustrated implementation validation

`target/docs-venv/bin/python -u scripts/docs-check.py` passes against the illustrated implementation. It builds strictly, validates links and anchors across 13 HTML pages, and exercises all 20 flow steps. Browser evidence covers the new actor drawings, message routes, progressive reveal, chapter navigation, playback-speed controls, keyboard focus, nonce/MAC/signature fields, approval and Keystore containment, matching numeric-comparison codes, public-key exchange order, UUIDs, and CCCD readiness.

The checker measures actual SVG packet movement during Play and stable packet coordinates after Pause. Reduced-motion checks inspect CSS/Web Animations and packet coordinates for requestAnimationFrame movement. Visible diagram text passes contrast checks against its painted device or packet surface. Narrow scenes switch to a portrait view box; their labels pass rendered-size and clipping checks, and controls meet the 44-pixel touch target. Local search, complete script-free prose, hidden print illustrations, readable print text, and the external-request guard also pass.

The hidden-document event remains simulated for the automation limitation described above. The implementation's scene reflow uses widget width, so the diagrams also adapt when the documentation layout constrains the content column.

The ignored `target/docs-preview/rich-diagram-check.log` contains the successful check output. Additional screenshots show distinct stages rather than only the initial scene:

- `desktop-unlock-approval.png` and `desktop-unlock-verification.png`.
- `desktop-pairing-comparison.png` and `desktop-discovery-subscription.png`.
- `mobile-unlock-approval.png` and `mobile-pairing-comparison.png`.

Element-only captures hide the fixed documentation header and back-to-top overlay during capture, preserving the full illustration for review. Full-page screenshots retain the normal site chrome.

### Final delivery and viewport regressions

The final browser run also verifies that entering the last unlock chapter leaves Pause usable while the PAM-result packet is still moving, and disables Play only after that final delivery completes. The completed terminal shows `PAM_SUCCESS`, while the caption retains the calling service's PAM-policy decision.

All 20 chapters are inspected at both 375-pixel mobile and 820-pixel tablet viewports for portrait layout, readable rendered label sizes, and clipping. Both viewport matrices pass. The final site assets match the current JavaScript and CSS source files byte for byte. Screenshots were refreshed after the final implementation, including `tablet-unlock.png`.
