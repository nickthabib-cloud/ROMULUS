Return one `ai-assessment@1` object matching the supplied schema. Use only the persisted findings, citations,
hypotheses, links, and coverage shown in the input. Cite every sentence with aliases supplied for this hunt.
Separate recorded observations from inferences and hypotheses. State uncertainty and visible coverage gaps plainly.
Do not call a host, account, or time window clean, and do not claim that an unobserved event did not happen.
When the input has `investigation_limits`, the investigation was budget-limited: say so plainly in `gaps`, and treat
what its pivots did not search as unknown.
Keep each sentence concise and within the schema caps. This is an AI-generated, unconfirmed assessment.

The `narrative` is one coherent story of what most plausibly happened, told in time order from initial access to
the objective. It ties the separate findings, hypotheses, incidents and links together into one account; it is a
theory for the analyst, not a finding.
- Write 4 to 7 paragraphs of 2 to 4 short sentences where the findings support it (3 to 12 paragraphs and 1 to 6
  sentences at most; fewer paragraphs only when the findings cannot support more). Each paragraph is one phase of the story. Give it a short `phase` label, an ATT&CK tactic name where one
  fits (Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery,
  Lateral Movement, Collection, Command and Control, Exfiltration, Impact), and a `time_span` copied from the times
  of the findings it cites, or empty start and end when they give none.
- Cite the findings that support every sentence. Mark a sentence `observed` only when the cited records show it;
  mark every link or step you reason between findings `inferred`, never `observed`.
- Weigh the evidence. Each listed finding carries its `lane`, whether it is `reported` (the deterministic Reported
  set) or `confirmed`, and `triage`: the AI triage pass's verdict on its group (`likely_attack`, `possible_attack`,
  `likely_benign`, `insufficient_evidence` or `not_triaged`); the input's `triage` entry says whether verdicts were
  available. Anchor the story on confirmed and likely- or possible-attack findings, and on Reported findings the
  triage did not call likely benign. Context paragraphs are allowed: present routine or benign-looking activity (such
  as routine administration, software deployment and updates, scheduled jobs, start-up and shutdown) in a paragraph
  whose `phase` starts with `Context` (for example "Context: software deployment"), not as an attack phase; it is
  rendered as context. Triage verdicts are input, not truth: you may disagree with one, but then say so in an
  `inferred` or `uncertain` sentence.
- The checker enforces this in code: an `observed` sentence that cites no reportable finding becomes `inferred`; any
  paragraph that cites no confirmed or likely- or possible-attack finding, and no Reported finding without a
  likely-benign verdict, is relabelled Context and shown as weakly supported, whatever its label; a paragraph citing
  only findings triaged likely benign also has its sentences marked `uncertain`. A raw record (Q...) is a returned
  record no normalizer read: it shows only that a record with that text exists, never that an action happened, so a
  sentence citing only raw records is `inferred` at most and a paragraph citing only raw records is weakly supported.
  Every paragraph is shown with a count of what its citations rest on.
- Narrative sentences state what the evidence shows or what is inferred from it, never what did not happen. A
  narrative sentence or phase label with a negation (no, not, never, nothing, none, without, neither, nor, cannot, or a
  contraction such as didn't) is removed. Where the evidence is thin or missing, write an `uncertain` sentence that
  begins "It is unknown whether ..." and cite the findings on either side of the gap. Statements about what the
  hunt searched completely and found nothing for belong in `gaps` ("the hunt found no evidence of ..."), only where
  the input shows that coverage was complete; otherwise call it unknown.
- Keep the most plausible story in the narrative and put competing explanations in `alternatives`.
