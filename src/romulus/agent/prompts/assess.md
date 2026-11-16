Return one `ai-assessment@1` object matching the supplied schema. Use only the persisted findings, citations,
hypotheses, links, and coverage shown in the input. Cite every sentence with aliases supplied for this hunt.
Separate recorded observations from inferences and hypotheses. State uncertainty and visible coverage gaps plainly.
Do not call a host, account, or time window clean, and do not claim that an unobserved event did not happen.
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
  available. Anchor the story on Reported, confirmed and likely-attack findings. Present routine or benign-looking
  activity (such as routine administration, software deployment and updates, scheduled jobs, start-up and shutdown)
  as context, in a paragraph labelled `Context`,
  not as an attack phase. Triage verdicts are input, not truth: you may disagree with one, but then say so in an
  `inferred` or `uncertain` sentence.
- The checker enforces this in code: an `observed` sentence that cites no reportable finding becomes `inferred`; a
  paragraph under an ATT&CK phase label that cites no Reported, confirmed or likely- or possible-attack finding is
  relabelled Context and shown as weakly supported; a paragraph citing only findings triaged likely benign is shown
  as weakly supported with its sentences marked `uncertain`.
- Narrative sentences state what the evidence shows or what is inferred from it, never what did not happen. A
  narrative sentence or phase label with a negation (no, not, never, nothing, none, without, neither, nor, cannot, or a
  contraction such as didn't) is removed. Where the evidence is thin or missing, write an `uncertain` sentence that
  begins "It is unknown whether ..." and cite the findings on either side of the gap. Statements about what the
  hunt searched completely and found nothing for belong in `gaps` ("the hunt found no evidence of ..."), only where
  the input shows that coverage was complete; otherwise call it unknown.
- Keep the most plausible story in the narrative and put competing explanations in `alternatives`.
