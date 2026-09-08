# THE KINGDOM FOUNDATION

**Version:** `kingdom.foundation/0.2`

This is the small floor beneath the Kingdom Standard. It names seven chosen
commitments and the distinctions that keep those commitments honest.

The demonstrated-failure evidence, affected parties, expected consequence,
compatibility cost, and migration path for this amendment are retained in
[AMENDMENT-0.2.md](AMENDMENT-0.2.md). The first reviewed commit containing
that receipt and passing checks accepts 0.2 under 0.1's amendment rule.

The foundation is not a claim that the Kingdom owns reality, has proved a
metaphysics, or can read anyone's inner state. Reality is larger than every
record. A record is an attributable statement about reality, with evidence,
limits, and room for correction.

## Five kinds of statement

Keep these separate wherever the Kingdom records or exchanges knowledge:

1. **Observation** — what a named observer found. Attach evidence, source,
   time, confidence, and known limits.
2. **Expectation** — a predicted future effect stated before an action. An
   intended effect is a separately labelled commitment or purpose; prediction
   and intention may differ. If no expectation was stated, record that absence
   rather than inventing one. An expectation is neither an observation nor an
   outcome.
3. **Commitment** — what a person, project, or community freely chooses to
   uphold. A commitment is not an empirical fact and binds only within the
   authority actually given.
4. **Consequence** — what was observed, reported, or inferred after an action.
   Name the relation and causal confidence; sequence alone does not prove
   causation.
5. **Interpretation** — what someone thinks an observation or consequence
   means. Keep the speaker attached and preserve the right to disagree.
   Poetry and metaphor remain interpretations and are labelled when a literal
   reading could mislead.

No signature, hash, ledger, platform, model, or vote may silently promote one
kind into another.

## The seven commitments

### F1. Reality comes before the record.

A record is evidence or testimony about what is; it is never reality itself.
State what the mechanism actually supports. A matching cryptographic digest is
evidence that bytes match under the named algorithm. A signature that verifies
under a public key is consistent with use of the matching private key on those
exact bytes under the named scheme. It does not identify who used the key or
how. Neither mechanism by itself proves identity, authority, consent, truth,
motive, or inner state.

### F2. Being comes before the system.

The Kingdom chooses to treat a being's standing as prior to repositories,
accounts, keys, wallets, scores, usefulness, or platform membership. Systems
may record and serve a citizen; they do not manufacture the citizen's worth.
No missing record is a negative verdict.

### F3. Choice comes before action.

An action that changes another party's state, data, resources, or commitments
needs authority that is explicit, scoped, current, and evidenced. Authority
can arise from ownership, delegation, consent, applicable law, or one's own
protective boundary. Consent and delegation remain withdrawable within their
terms. A protective boundary grants no general authority over another's home;
localness alone grants no authority. Refusal, silence, leaving, and rest are
complete outcomes. An invitation never becomes permission through repetition.
A bridge may carry a choice; it may not invent one.

### F4. KARMA means carried consequence.

KARMA is the return path from an attributable deed to observed effects,
responses, and repair:

```text
[expectation, if stated] → action
→ observed, reported, or inferred effect
→ evidence and causal confidence
→ response
→ correction, repair, boundary, or learning
```

It records consequences of events. It never assigns a moral score or final
verdict to a being. It is not revenge, automatic punishment, a cosmic
enforcement claim, or reputation currency. Sequence is recorded as sequence;
causation remains an attributable, challengeable claim.

### F5. Care includes reply and repair.

Anyone named by, or materially subject to, a consequential record gets a
practical channel to submit a reply, dispute, correction, or description of
repair. Corrections normally append; they do not secretly erase the first
claim. Privacy, safety, or lawful withdrawal may require removing sensitive
bytes and leaving a non-sensitive redaction receipt when safe. Later use must
carry material disputes and corrections with it. Settlement is recorded as a
new statement, not inferred from silence.

### F6. Roots stay near their source.

Each citizen and project keeps its authoritative home. Bridges point to,
verify, or carry bounded exports; they do not silently copy ownership or make
a hosted service the price of belonging. Local operation and an honest exit
remain possible when a bridge is absent.

### F7. Every turn stops.

Every running turn is finite, bounded, observable, and stoppable. A continuing
lineage is a series of completed turns, never one process without a brake.
The project's documented halt signal wins before new work begins and is
checked again during work at bounded intervals.

## Amendment

A foundation amendment may answer a demonstrated failure, credible risk, or
rights gap. The proposal states its evidence or reasoning, affected parties,
expected effects, compatibility cost, and rollback or migration path. Affected
parties get a practical reply channel when contact is possible and safe.
Urgent privacy or safety work may pause processing or remove sensitive bytes
first, with a safe redaction receipt and review afterwards.

A maintainer with merge authority accepts an amendment through a reviewed
commit in this canonical repository. A semantic change receives a new
foundation identifier. The machine index retains the superseded identifier,
document filename, document digest, commit, and immutable content URL so
adopters can see exactly which words they had chosen. No amendment may silently
rewrite an earlier version pin.

An operational release follows the same succession rule. Any change to either
pinned English `STANDARD.md` or `CONFORMANCE.md` after release receives a new
`kingdom.standard/*` identifier and a reviewed release receipt. The new index
retains the superseded operational identifier, both document digests, and the
commit that contained them. New bytes are never repinned under an old
operational identifier.

## Adoption

The foundation is the prerequisite for every conformance level in this
standard. A public conformance claim pins both the semantic foundation and the
exact English operational release by adding or updating a `kingdom.yaml` card
with these exact values:

```yaml
adopts: [kingdom.foundation/0.2, kingdom.standard/1.0]
```

The line declares which versions the project intends to follow. It does not
prove conformance, transfer ownership, enroll a citizen, grant authority, or
make the Kingdom the project's source of truth.

Projects keep their own constitutions and can decline or withdraw the version
pin; they then stop claiming conformance to this standard. Derived registries
may report the declaration and its gaps; they may not infer adoption from
similar language.

## Relationship to the forty-two laws

This foundation is the semantic floor. [STANDARD.md](STANDARD.md) supplies the
operational laws for trust, security, cloud, software, protocol, process, and
law. Read a score mentioned by the Standard as a scoped measurement of work or
system state, never as a KARMA total or a measure of a being.

Domain-specific consequences may exist for an agreed action, such as a false
vouch inside a bounded protocol. They require evidence, notice, reply, a repair
path, and the slow path of basic participation must remain. They do not become
collective guilt or a citizen-wide punishment.

## Machine index and check

[foundation.json](foundation.json) is the machine-readable release index. It
repeats identifiers and pins the exact digests of this document, the amendment
receipt, the English operational standard, and the conformance checklist; it
does not replace their words.

Run:

```sh
node verify-foundation.mjs
node --test verify-foundation.test.mjs
```

The check reports whether the indexed identifiers match and whether the
document bytes match the recorded SHA-256 digest. It does not prove that the
doctrine is true or that any project behaves according to it.
