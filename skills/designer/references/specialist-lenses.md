# Designer Specialist Lenses

Use these lenses when the main `SKILL.md` matrix is too thin for the surface.
The goal is repeatable severity, not vague taste.

## 1. Surface And Domain Lens

First classify the surface:

- Marketing / landing page
- Product app / dashboard / tool
- Ecommerce / checkout / product listing
- Blog / editorial / content page
- Form / onboarding / settings
- Data-heavy table/list/workflow
- Component / design-system element

Ask: what would a specialist in this surface punish?

- SaaS dashboard: weak scan density, unclear state, too much hero drama, slow repeated actions.
- Landing page: unclear offer, no primary CTA, weak proof, generic hero, no product truth above fold.
- Checkout: hidden cost, unclear required fields, poor error recovery, trust gaps, placeholder-only labels.
- Blog/content: poor reading width, weak headings, bad byline/date affordance, no content hierarchy.
- Desktop app: small-window fit, menu/toolbar density, keyboard path, focus, state persistence.

## 2. Cognition And Flow Lens

Specialist questions:

- What is the user's next action within 3 seconds?
- Is there one primary action per view or section?
- Are similar choices grouped or forced into comparison?
- Can the user recover from a mistake?
- Does the UI disclose complexity gradually?
- Does the visible state match the user's mental model?

Fail patterns:

- Equal-weight CTAs.
- Hidden primary action.
- Forced account creation or payment before trust is earned.
- Errors with no recovery action.
- Multi-step flows with no progress/context.

## 3. Visual Hierarchy Lens

Specialist questions:

- Squint test: can the first/second/third read still be seen?
- Does size, weight, position, color, and whitespace agree?
- Is the CTA visually dominant for the right reason?
- Are decorative elements louder than utility?
- Is proof/detail visible where the decision happens?

Fail patterns:

- Everything same size/weight.
- CTA competes with secondary links.
- Big hero text in compact app panels.
- Cards used to compensate for weak grouping.
- Decorative gradient/image takes the first read away from the task.

## 4. Layout, Spacing, And Whitespace Lens

Specialist questions:

- Is spacing doing grouping before borders do?
- Are paddings/radii concentric?
- Are repeated controls dimensionally stable?
- Does density match the domain: calm page vs repeated-use app?
- Does the layout breathe without becoming empty?

Fail patterns:

- Nested cards.
- Accidental alignment relationships.
- Random 12/14/17/23px spacing drift.
- Large whitespace used to hide lack of information.
- Dense dashboards with no scan lanes.
- Mobile/tablet text overflow or horizontal scroll.

## 5. Typography Lens

Specialist questions:

- Is the typeface a product/brand decision or a default?
- Are headings balanced and readable at each breakpoint?
- Are body lines around 65-75ch for reading surfaces?
- Do numbers use tabular figures when changing/scanning?
- Does the type scale fit the container?

Fail patterns:

- Inter/system font as the whole visual idea without brand reason.
- Display scale inside compact controls.
- Muted body copy that looks elegant but is unreadable.
- Line heights too tight for long text or too loose for dense app UI.
- Long labels causing toolbar/card shifts.

## 6. Color, Contrast, And Semantics Lens

Specialist questions:

- What does every strong color mean?
- Are action, selection, focus, success, warning, error, proof, and destructive roles distinct?
- Is the palette product-true or category-default?
- Does contrast hold in actual rendered backgrounds?
- Is state communicated by more than color?

Fail patterns:

- Default Tailwind blue `#3B82F6` as a brand.
- Purple-blue "AI/SaaS" gradient with no product truth.
- Beige/cream or dark-slate monoculture chosen by reflex.
- Green used for both success and primary action when it confuses state.
- Disabled text unreadable.
- Placeholder text too low contrast.

## 7. Iconography, Imagery, And Assets Lens

Specialist questions:

- Does each icon carry information or just decorate?
- Are icon weights, corner styles, fills, and sizes consistent?
- Are labels/tooltips present where icons are not universal?
- Does the page show the real product/place/object when inspection matters?
- Are brand/product assets real, current, and sharp?

Fail patterns:

- Icon beside every heading.
- Mixed lucide/emoji/custom glyph soup.
- Generic abstract screenshots or fake UI when real product UI exists.
- CSS silhouette replacing a product shot.
- Stock image that does not change comprehension.
- Broken images, visible alt text, placeholder graphics.

## 8. Interaction-State Lens

Inventory control groups before judging:

- Nav, tabs, segmented controls
- Toolbar/icon buttons
- Cards/list rows
- Menus/popovers/dialogs/drawers/tooltips
- Forms/inputs/selects/sliders/toggles
- Tables, filters, pagination
- Destructive actions and confirmations

For each group, inspect or mark untested:

- Default
- Hover
- Focus
- Pressed/clicked
- Active/current/selected
- Disabled/unavailable
- Loading
- Error
- Empty
- Expanded/open/dismissed
- Edge cases: long labels, adjacent hover, overflow clipping, keyboard use

Fail patterns:

- No focus ring.
- Hover shifts layout.
- Selected looks like hover.
- Disabled still looks clickable.
- Popover clipped by overflow.
- Error is red border only.
- Loading spinner hides content shape.

## 9. Motion And Micro-Interaction Lens

Use this lens hard. Motion quality often reveals whether the UI was actually
crafted.

Specialist questions:

- Should this animate at all, given frequency?
- What is the UX purpose?
- Does the motion start responsive and end calm?
- Does it preserve spatial continuity?
- Is it interruptible?
- Does reduced motion preserve comprehension?
- Does timing match the product personality?

Pass rules:

- Buttons have subtle tactile press feedback where useful.
- Popovers originate from triggers; modals from center.
- Enter/exit motion is asymmetric when appropriate: exits softer/faster.
- Skeletons or stable placeholders beat generic spinners for content loading.
- Motion uses transform/opacity where possible.
- Transitions name exact properties.

Fail patterns:

- Animation on keyboard-triggered command palette or frequent workflow.
- `transition: all`.
- `ease-in` on UI response.
- Duration above 300ms for frequent UI.
- `scale(0)` entry.
- Bouncy/elastic motion in a serious work tool.
- Scroll reveal leaves content blank in screenshots/headless capture.
- Confetti/delight blocks the actual save/confirm state.

## 10. Accessibility Lens

Specialist questions:

- Can keyboard users reach, operate, and escape every important control?
- Are custom widgets using correct ARIA patterns?
- Are labels real labels, not placeholders?
- Are errors associated with fields and announced?
- Is focus visible and unclipped?
- Does motion respect `prefers-reduced-motion`?
- Is the page title/lang/landmark structure sane?

Fail patterns:

- Missing accessible name on core icon button.
- Keyboard trap in modal/menu.
- Focus outline removed with no replacement.
- Error state is color-only.
- Body text below 4.5:1 contrast.
- Tiny hit targets on touch screens.

## 11. Performance-Perception Lens

Specialist questions:

- Does loading communicate shape and progress?
- Do layout shifts happen during input or load?
- Does the UI feel responsive under interaction?
- Are animations likely to stay smooth under load?
- Are expensive effects used only where they matter?

Fail patterns:

- Full-page spinner where a skeleton should exist.
- Blank sections that rely on JS/reveal timing.
- Input causes visible re-layout.
- Large blur/backdrop/filter on frequently moving surfaces.
- Framer/Motion main-thread transforms on hot paths where CSS would do.

## 12. Brand, Domain, And Anti-Slop Lens

Specialist questions:

- Could this be another product if the logo changed?
- Is there a nameable visual or interaction signature?
- Does the first viewport reveal the actual product/service/place/object?
- Are colors, type, assets, and motion derived from product truth?
- Is content real, useful, and specific?

Fail patterns:

- Same SaaS hero, same card grid, same purple gradient.
- Fake stats, fake quotes, fake testimonials, fake "trusted by" proof.
- Tiny uppercase eyebrow on every section by reflex.
- Numbered section markers where the content is not actually sequential.
- Rounded everything with no material logic.
- "Premium" created only by beige, gold, or dark slate.

## 13. Specialist Output Standard

For each finding, include:

- Lens name.
- Visible evidence or tested state.
- User consequence.
- Exact fix.
- Confidence: high for mechanical/visible, medium/low for taste judgment.

Bad finding:

> The page feels generic.

Good finding:

> Lens 12 / Brand-domain specificity: the hero uses a centered headline, two
> equal CTAs, purple-blue gradient, and abstract cards. Consequence: after the
> logo swap, this could be any AI SaaS, so users do not learn what is specific
> about this product. Fix: replace the abstract hero with a live product
> mechanism showing the actual workflow state, make one primary CTA dominant,
> and derive accent color from a real product state/token.
