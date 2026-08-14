# KDP Official Requirements

Verified against Amazon KDP help pages on 2026-05-13. Re-check official KDP pages before upload, pricing, AI disclosure, or policy-sensitive decisions.

## Official Source Links

- Metadata guidelines: https://content kdp.amazon.com/en_US/help/topic/G201097560
- Book titles and editions: https://content kdp.amazon.com/en_US/help/topic/GW7J4WEKBVU25YEC
- Paperback submission guidelines: https://content kdp.amazon.com/en_US/help/topic/G201857950
- Format your paperback: https://content kdp.amazon.com/en_US/help/topic/G201834190
- Save your manuscript file: https://content kdp.amazon.com/help/topic/G202145060
- Format images in your book: https://content kdp.amazon.com/en_US/help/topic/G202169030
- Print options and trim sizes: https://content kdp.amazon.com/en_US/help/topic/G201834180
- Trim size, bleed, and margins: https://content kdp.amazon.com/en_US/help/topic/GVBQ3CMEQW3W2VL6/
- Fix paperback/hardcover formatting issues: https://content kdp.amazon.com/en_US/help/topic/G201834260
- KDP content guidelines and AI disclosure: https://content kdp.amazon.com/en_US/help/topic/G200672390
- Create a paperback cover: https://content kdp.amazon.com/en_US/help/topic/G201953020
- Cover calculator/template generator: https://content kdp.amazon.com/cover-calculator
- Book detail resources: https://content kdp.amazon.com/en_US/help/topic/G202105800
- Keywords: https://content kdp.amazon.com/en_US/help/topic/G201743260
- Categories: https://content kdp.amazon.com/en_US/help/topic/G200652170
- Book description: https://content kdp.amazon.com/en_US/help/topic/G201189630
- Low-content books: https://content kdp.amazon.com/en_US/help/topic/GGE5T76TWKA85DJM
- Kindle content quality: https://content kdp.amazon.com/en_US/help/topic/G200952510

## Print Interior

- Upload a manuscript/interior file and a separate cover file for paperback.
- Use single pages, not spreads or 2-up files.
- Choose a KDP-supported trim size or a valid custom paperback trim. KDP says custom paperback trim width must be 4 in to 8.5 in and height must be 6 in to 11.69 in. Large trim size affects printing cost.
- For no bleed, page size equals trim size.
- For full bleed, extend content 0.125 in / 3.2 mm beyond trim on top, bottom, and outside edges.
- Embed fonts.
- Minimum interior font size: 7 pt.
- Image resolution: minimum 300 DPI.
- Line art should be at least 0.75 pt / 0.01 in / 0.3 mm.
- All pages/content should share the same orientation.

## Interior Image Actuals Gate

Run this before saying coloring/activity page images are ready for PDF layout:

- Confirm the final trim and bleed choice first. For no bleed, page pixels must equal trim size x 300 DPI or better. For 8.5 x 11 in no bleed, use 2550 x 3300 px. For 8.5 x 11 in full bleed, use 2625 x 3375 px.
- Confirm every page image uses one identical canvas size. Mixed PNG sizes are not print-ready even when the art looks fine in a folder.
- Confirm effective resolution is at least 300 DPI at final print size. Do not treat metadata DPI alone as proof if the pixel dimensions are too small.
- Flatten transparency and use RGB for image/PDF assembly unless the layout tool has a deliberate CMYK workflow.
- Check safe margins against the final page count. For 24-150 pp no-bleed interiors, keep live content at least 0.375 in from the inside/gutter and at least 0.25 in from outside edges.
- For line-art coloring pages, inspect at 100 percent zoom for crisp edges, broken lines, gray anti-alias haze, accidental shading, or low-resolution wobble.
- Scan outer trim edges for unintended dark pixels or black frame artifacts.
- Rerun a brief-diff against the locked art specs. A print-correct page can still fail if it misses required subjects, props, text, or exclusions.

Use precise status language:

- "Interior images are PDF-layout ready" means the individual page assets pass size, mode, margin, and brief checks.
- "Interior PDF is upload-ready" means the assembled PDF also passes page size, embedded fonts, no crop marks, no placeholder text, and local proof inspection.
- "KDP-ready" is reserved for the full product: upload-ready interior PDF, upload-ready cover PDF, metadata/listing, AI disclosure, and proof-preview checks.

## Minimum Margins

| Page count | Inside/gutter | Outside no bleed | Outside with bleed |
|---:|---:|---:|---:|
| 24-150 | 0.375 in / 9.6 mm | at least 0.25 in / 6.4 mm | at least 0.375 in / 9.6 mm |
| 151-300 | 0.5 in / 12.7 mm | at least 0.25 in / 6.4 mm | at least 0.375 in / 9.6 mm |
| 301-500 | 0.625 in / 15.9 mm | at least 0.25 in / 6.4 mm | at least 0.375 in / 9.6 mm |
| 501-700 | 0.75 in / 19.1 mm | at least 0.25 in / 6.4 mm | at least 0.375 in / 9.6 mm |
| 701-828 | 0.875 in / 22.3 mm | at least 0.25 in / 6.4 mm | at least 0.375 in / 9.6 mm |

### Asymmetric safe area and visual centering

KDP's safe-area margins are intentionally asymmetric: the gutter side is wider than the outside. The KDP Print Previewer draws this safe area as a dashed guide, and the guide is therefore offset away from the gutter by the difference between the two margins. A page that is centered in its source canvas (so centered to the trim) is NOT centered in the safe area — it sits closer to the gutter-side dashed line than to the outside-side dashed line. On the bound printed book, the binding curve hides ~0.125 in near the spine, so trim-centered content reads as pulled toward the spine.

For visually centered content on a bound book, center designs in the safe area, not the trim, by applying a per-page horizontal shift keyed on output-position parity:

- Odd output positions (right-hand pages, gutter on left): shift the page right by half the margin asymmetry.
- Even output positions (left-hand pages, gutter on right): shift the page left by half the margin asymmetry.

For 24-150 pp at 300 DPI, the asymmetry is (0.375 in - 0.25 in) = 0.125 in, so the per-page shift is ~19 px (0.0625 in / 1.6 mm). For 151-828 pp the asymmetry is larger; compute (gutter - outside) / 2 and scale by DPI.

Recenter any source images whose ink bounding box is materially off-center in the source canvas before applying the gutter shift; otherwise the source skew compounds with the binding-aware shift.

## Cover

- Covers are one continuous image: back + spine + front.
- Bleed: 0.125 in / 3.2 mm on all sides.
- Keep non-trim content at least 0.25 in / 6.4 mm from outside cover edge.
- Flatten layers and embed fonts.
- KDP only prints spine text on books with more than 79 pages. If manuscript is under 80 pages, do not include spine text.
- If using KDP's automatic barcode, leave the lower-right back cover clear. Low-content barcode box is 2 in x 1.2 in.
- Use KDP's cover calculator/template generator after the final page count, trim, paper, and ink choices are locked. Back-of-envelope pixel math is acceptable for planning, not for final upload sizing.
- Do not assume the inside front cover is available as a printable surface for paperback. Treat cover design as the exterior full wrap unless KDP/product settings explicitly support another surface.

## Color Guidance For Coloring Books

- KDP paperback interiors use the selected ink/paper option for the whole interior file. Do not add a color reference page to a black-and-white interior without flagging the pricing/product consequence.
- For black-and-white coloring books, keep interior color guidance in black type only, or move visual color references to the back cover, Amazon listing images, or A+ content.
- For mythology/kids books where color carries meaning, a short B&W note is often enough: "Krishna is often shown with soft blue skin. You can color him that way, or color him however you imagine him."
- Back-cover colored mini thumbnails can serve both as a parent/kid color cue and as Amazon marketing imagery without changing B&W interior printing.

## Spine Width

Calculate spine after the final interior page count is locked. KDP formulas:

- black and white on white paper: page count x 0.002252 in
- black and white on cream paper: page count x 0.0025 in
- color interior: page count x 0.002347 in

Cover width formula:

`bleed + back cover width + spine width + front cover width + bleed`

Cover height formula:

`bleed + trim height + bleed`

Paper choice affects the spine and reader feel. Use white paper for most activity/coloring books. Use cream only when the book is text-led and the warmer novel/journal feel is intentional. Recalculate cover dimensions if paper, ink, trim, or page count changes.

## File Format

- Use PDF for final print files unless the specific KDP path calls for another accepted format.
- File size must not exceed 650 MB.
- Export with embedded fonts.
- Flatten transparencies/layers before upload.
- Remove crop marks, trim marks, comments, annotations, invisible objects, and metadata clutter.
- If the design tool supports a print-ready PDF/X export, use it only after confirming it preserves KDP size, bleed, embedded fonts, and image quality.
- Inspect in KDP Print Previewer; do not assume local PDF rendering equals KDP output.

## Common Rejection / Failure Points

KDP flags issues such as:

- locked/encrypted files
- crop marks, trim marks, comments, annotations
- placeholder text
- missing pages
- excessive blank pages
- title missing on front cover
- barcode issues
- incorrect pagination
- PDF creation watermarks/logos
- cover size errors
- margin/gutter errors
- transparencies
- illegible text
- low-resolution images

## AI Content

KDP requires publishers to inform Amazon of AI-generated content, including text, images, or translations, when publishing a new book or editing/republishing an existing book. KDP distinguishes AI-generated content from AI-assisted content; answer the upload form accurately based on how the text/images/translations were created and edited.

Do not put awkward AI disclosure in reader-facing pages unless policy requires it. Do disclose correctly in the KDP upload form.

## Low-Content

KDP defines low-content books as minimal/no-content interiors that are generally repetitive and designed to be filled in. Examples include notebooks, planners, diaries/journals, prompt journals, log books, and habit trackers.

KDP says activity books such as puzzle books and coloring books are generally not low-content because they do not generally feature repetitive content on each page, but exceptions can exist.

Low-content constraints include:

- must be marked low-content where applicable
- not eligible for free KDP ISBN
- series not eligible for low-content books
- some Look Inside/read sample limitations without own ISBN

## Metadata

- Title and subtitle together must be 200 characters or fewer and must match the cover.
- Do not put HTML, sales rank claims, promotions, unauthorized trademarks, or generic keyword stuffing in title/subtitle.
- Description limit is 4000 characters.
- KDP lets authors choose up to 7 keyword slots. Avoid vague terms.
- Do not use HTML tags in keyword fields.
- Keep keyword slots concise; verify current per-slot limits in the KDP UI before upload.
- KDP allows 3 categories. Pick accurate categories where buyers actually browse.
- Book detail fields can be hard or impossible to change after publishing; double-check before upload.
- Amazon recommends simple, compelling, professional book descriptions that avoid overwhelming details.

## Quality Standard

Amazon warns against disappointing customer experiences, including too-short content, poor translation, inaccurate content, excessively reused/recycled/repeated content, misleading metadata, or content that primarily advertises/redirects.
