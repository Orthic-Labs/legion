# Drafting Standards — Consumer Complaint Pack

The house style for a District Commission filing pack, distilled from prior consumer-complaint drafting practice. The generator (`scripts/generate_pack.py`) produces all of this from the case YAML — this file is the spec the generator follows and the checklist a human uses to review the output.

---

## The six documents

| # | File | Contains |
|---|---|---|
| 1 | Index | Table of contents (6 numbered items + annexure list), with conventional page ranges |
| 2 | Proforma | A numbered fact-sheet table — parties, jurisdiction, amounts, relief, limitation |
| 3 | Synopsis + List of Dates | A prose synopsis, then a two-column DATE / EVENT table |
| 4 | Memo of Parties | The cause title block — complainant vs opposite parties, full addresses |
| 5 | Consumer Complaint + Affidavit | The main petition (numbered paragraphs, RESPECTFULLY SHOWETH … PRAYER), Verification, then the notarised Affidavit |
| 6 | Party-in-Person Declaration | Standalone declaration that the complainant files without an advocate |

## Formatting

- **Font:** Times New Roman, 12 pt body. Headings bold, centred.
- **Top of every document** (the cause title), centred and bold:
  ```
  BEFORE THE DISTRICT CONSUMER DISPUTES REDRESSAL COMMISSION, <DISTRICT>
  CONSUMER COMPLAINT NO. ______ OF <YEAR>
  ```
  The complaint number stays blank — the registry fills it.
- **Tables:** bordered. Index = 3 columns (S.No / Particulars / Page No). Proforma = 3 columns (item no / label / value).
- **Party block** (Memo and the head of the Complaint):
  ```
  IN THE MATTER OF:
  <Name>, aged <N> years,
  S/o Mr. <Father's name>
  R/o <full address>
  Email: <e> | Mobile: <m>
                                          … COMPLAINANT
  VERSUS
  1. <OP-1 legal name> (operating as "<brand>" through <site>)
  CIN: <cin>
  Registered Office: <addr>
  Email: <e> | Phone: <p>
  Through its Authorized Officers and Directors
                                          … OPPOSITE PARTY NO. 1
  2. <OP-2 …>
                                          … OPPOSITE PARTY NO. 2
  ```
- **Foot of every document:**
  ```
  Place: <City>
  Date: ___________ <Month> <Year>          <- day blank, filled by hand at signing/notarisation
                                  (<Name>)
                                  Complainant
  ```
- **Complaint body:** opens `RESPECTFULLY SHOWETH:` then consecutively numbered paragraphs; sections `CAUSE OF ACTION`, `LIMITATION`, `JURISDICTION`, `GROUNDS`, `PRAYER`; closes `AND FOR THIS ACT OF KINDNESS THE COMPLAINANT, AS IN DUTY BOUND, SHALL EVER PRAY.`
- **Verification** (immediately after the prayer): "I, <Name>, the Complainant above-named, do hereby solemnly verify that the contents of paragraphs 1 to <N> … Verified at <City> on this _____ day of <Month>, <Year>."
- **Affidavit** (new page, own cause title): "I, <Name>, son of Mr. <Father>, aged about <N> years, by faith <faith>, presently residing at <addr>, do hereby solemnly affirm …" — numbered averments, then a Verification of Affidavit, then:
  ```
  Identified by me:

  Advocate / Notary Stamp & Seal Below:
  ```

## Cross-references the generator must derive (never hand-type)

These drifted in prior manually-drafted packs and caused real defects. The generator computes them from the case YAML:

- **"paragraphs 1 to N"** in the Verification and the Affidavit — N = the actual count of numbered complaint paragraphs.
- **"Annexures A-1 to A-N"** in the Affidavit — N = the actual count of annexures in the Index.
- **Index rows** — generated from the annexure list, not typed twice.
- **Affidavit averment** about annexures being true copies — the count must match the Index.

If facts change, **regenerate** — do not hand-patch one document.

## Blanks — what stays empty and who fills it

| Blank | Who fills it | Never auto-fill |
|---|---|---|
| `CONSUMER COMPLAINT NO. ______ OF <YEAR>` | The Commission's registry, after submission | Yes — leave blank |
| Day-of-month in `Date: ___________ <Month> <Year>` | The complainant, by hand, at signing/notarisation | Yes — leave the day blank, fill month + year |
| Day-of-month in `Verified … this _____ day of <Month>, <Year>` | Same | Yes — leave the day blank, fill month |
| "Identified by me" / "Notary Stamp & Seal" | The notary | Yes |

Father's name, ages, addresses, amounts, party details, dates of events — all come from the case YAML and **must be filled**. No `(father's name)`-style placeholder annotations in the output.

## Consumer-status framing — get this right

The opposite party's first defence is often "you are not a consumer." Pick the framing that fits the facts and plead it explicitly in Proforma item 6 and an early complaint paragraph:

| Situation | Framing | Strength |
|---|---|---|
| Invoice / order in the complainant's **personal name**, goods/services for personal use | Plain consumer under S.2(7). State it simply. | **Strong** — straightforward |
| Invoice in the complainant's **personal name**, even though a related business benefited | Lead on the personal-name invoice → plain personal consumer status under S.2(7). | **Strong** — the invoice controls |
| Payment made from a **business account** for a service the business needed | Rely on the **livelihood / self-employment exception** to the commercial-purpose exclusion in S.2(7): the business is a one-person company that is the complainant's exclusive means of earning a livelihood by self-employment. Plead the OPC structure, sole director/member, livelihood dependence. | **Argued** — must be pleaded carefully; flag to the user it is contestable |

Never overstate status. If it is the "argued" path, say so to the user and recommend a lawyer's eye.

## Tone and substance rules

- Formal, third-person ("the Complainant"), past tense for facts.
- Every factual averment should be tied to an annexure where one exists ("… as evidenced by Annexure A-3").
- Quote the opposite party's own words where they admit or contradict — verbatim, in quotation marks, dated.
- Plead a **continuing wrong** in the Cause of Action where the conduct is ongoing (unanswered demands, an expired cure-period notice) — and date the most recent triggering event, because limitation runs from it.
- The **Prayer** must ask only for reliefs a District Commission can actually grant (refund, removal of deficiency, compensation, interest, costs, direction to correct an unfair practice). Map it to S.39. See `cp-act-2019.md`.
- **Never fabricate** a fact, date, amount, quote, docket, or annexure. If a fact is not in the case YAML and not in the user's evidence, it does not go in the draft.

## Review checklist (run on generator output)

```
[ ] Cause title correct; complaint number left blank
[ ] Every OP in Memo == every OP in Complaint head == parties to be entered on portal
[ ] Consumer-status framing matches the facts; flagged if "argued"
[ ] Jurisdiction: pecuniary tier + named S.34(2) limb + within S.69 limitation
[ ] Every statute citation checked against cp-act-2019.md; [UNVERIFIED] ones web-confirmed
[ ] "paragraphs 1 to N" and "Annexures A-1 to A-N" derived, not typed
[ ] Index annexure list == annexures the user actually holds as PDFs
[ ] Prayer maps to reliefs a District Commission can grant
[ ] Only intended blanks remain (complaint number, day-of-date, notary block)
[ ] No fabricated facts; quotes verbatim and dated
[ ] Lawyer review of legal substance recommended to the user
```
