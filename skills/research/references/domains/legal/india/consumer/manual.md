# Consumer Court (India)

PRIMARY_DELIVERABLE: Bounded consumer-court drafting or filing guidance for frozen case materials.
SPECIALIST_REFS_MAX: 0
CHILD_AGENTS_MAX: 0
EXTERNAL_REQUESTS_MAX: 12
MAY_ADD_TASKS: NO
MAY_CALL_SKILLS: NONE
TERMINAL: Requested legal deliverable meets frozen D3 source budget.

Drafting and filing support for Indian consumer disputes: District Consumer Disputes Redressal Commission complaints under the Consumer Protection Act, 2019, filed through the e-Jagriti portal. Turns a single case spec into the complete six-document filing pack.

This skill is a **drafting and logistics tool, not legal advice and not a substitute for counsel.** It supports a complainant who has chosen to file party-in-person. Recommend a lawyer's eye on the legal substance before anything is notarised or filed.

## Non-negotiable — verify the law, never recall it

Indian consumer law is the kind of factual claim CLAUDE.md non-negotiable #2 governs: section numbers, pecuniary limits, fee slabs, limitation periods, portal rules. The reference files tag every legal fact `[VERIFIED <date>]` or `[UNVERIFIED]`.

- Any `[UNVERIFIED]` item must be WebSearch-confirmed against the bare act (indiacode.nic.in) or the official portal **before** it goes into a draft, a filing step, or advice to the user.
- Never state an Indian statute, limit, or fee from memory.
- Re-verify anything time-sensitive against the current date — amendments and fee notifications change these.
- When unverifiable, say "unverified" — do not state it confidently.

## First choice — read only what the task needs

| Task | Read |
|---|---|
| Which commission, pecuniary/territorial jurisdiction, limitation, filing fees | `references/jurisdiction-and-fees.md` |
| Cite or check a Consumer Protection Act 2019 section | `references/cp-act-2019.md` |
| Draft the pack, document formatting, consumer-status framing | `references/drafting-standards.md` |
| File on the portal — steps, what to upload, account setup | `references/ejagriti-filing.md` |
| Generate the six-document pack | Not shipped: `generate_pack.py` is a repository-only script (`src/lib/research-core/workflows/legal/india/consumer/scripts/`), unavailable from the installed plugin. Assemble manually per `references/drafting-standards.md` until it is ported natively. |

## The filing lifecycle

1. **Intake** — build the case spec from `scripts/case-template.yaml`. One YAML per matter. It lives in the matter's own folder, never inside this skill (it holds personal data).
2. **Pre-litigation** — register an NCH grievance (consumerhelpline.gov.in) and send a warning/notice email with a stated cure period. Both strengthen the complaint. NCH is mediation only — not a forum, not a substitute for filing.
3. **Draft** — run the generator → six .docx files. The author supplies the legal substance (facts, grounds, prayer narrative) in the YAML; the generator owns structure, numbering, cross-references and boilerplate.
4. **Verify** — statute citations confirmed; consumer-status basis sound; cross-references derived not hand-typed; the annexure list matches the annexures actually held.
5. **Notarise** — print, sign, and notarise the Consumer Complaint + Affidavit before a notary. The day-of-month in the date is filled by hand at notarisation.
6. **File** — e-Jagriti portal: case type → case details → complainant → opposite parties → upload the pack + annexures → submit.

## Operating rules

1. **Verify the law** before citing it — the hard gate above.
2. **One source of truth per matter** is the case YAML. Every document derives from it. No copy-pasting paragraphs between cases — that is exactly what caused facts from one case to bleed into another in prior manually-drafted packs.
3. **The generator owns structure; the human owns legal substance.** Do not auto-write legal argument. Structure (headings, paragraph numbering, the six-file split, Verification/Affidavit boilerplate, Index rows, annexure counts, "paragraphs 1 to N" cross-refs) is mechanical and error-prone — automate it. Facts and law are not — author them, then have them reviewed.
4. **Consumer status is case-specific.** Get it right (see `drafting-standards.md`): an invoice in the complainant's personal name gives clean status; a purchase paid by the complainant's business relies on the livelihood / self-employment exception to the commercial-purpose exclusion in S.2(7); flag weak ones honestly.
5. **Never fabricate** facts, dates, amounts, docket numbers, parties, or correspondence. Blanks that the filer or the registry must fill — the day-of-month in the signing date, the court case number — stay blank. Do not invent them.
6. **Recommend a lawyer's review** of the legal substance before filing.
7. **PII discipline** — case YAMLs hold personal data (names, addresses, IDs). Keep them in the matter folder; never commit them to shared repositories.

## Output format

The generator emits, per case, into the matter's output folder:

```
NN_<Case>_Index.docx                          Index / table of contents
NN_<Case>_Proforma.docx                       Proforma fact-sheet
NN_<Case>_Synopsis_and_Dates.docx             Synopsis + List of Dates and Events
NN_<Case>_Memo_of_Parties.docx                Memo of Parties
NN_<Case>_Consumer_Complaint_with_Affidavit.docx   Main petition + Verification + Affidavit (NOTARISE this one)
NN_<Case>_Party_In_Person_Declaration.docx     Self-representation declaration
```

After generating, report a verify checklist:

```markdown
Verdict: READY TO NOTARISE / NEEDS FIX
Statute citations: [list each section cited + its [VERIFIED]/[UNVERIFIED] status]
Consumer status: [basis + whether it is clean or argued]
Jurisdiction: [commission + pecuniary fit + territorial basis + within limitation Y/N]
Cross-refs: [para count, annexure range — derived by generator, not hand-typed]
Blanks remaining: [should be only: day-of-date (filer), court case number (registry)]
Annexures: [count listed vs count the user confirms they hold]
Lawyer review: recommended before notarising — flag anything legally thin.
```

## Common failure modes

- Stating a section number, fee, or limit from memory instead of verifying it.
- Copy-pasting paragraphs between cases, so facts from case A bleed into case B.
- Hand-typing cross-references ("paragraphs 1 to 25", "Annexures A-1 to A-12") that then drift when the facts change — let the generator derive them.
- Filling the day-of-date or the court case number — those belong to the filer and the registry.
- Treating an NCH docket as a court filing — NCH is mediation only.
- Wrong commission — both pecuniary (value of consideration paid) and territorial (where the complainant resides, or an OP works, or the cause of action arose) must fit.
- Missing the limitation period (two years from cause of action, S.69).
- Asserting consumer status for a business buyer without addressing the commercial-purpose exclusion.
- Listing annexures in the Index that the complainant does not actually hold as scannable documents.
