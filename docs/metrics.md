# Report metrics — what the numbers mean

Every report opens with a `summary`. This page states exactly what each number
counts and, more importantly, **what it divides by** — a rate with an unstated
denominator is not a measurement.

## Outcome counters

| Key | Counts |
|---|---|
| `total` | findings assessed in this run |
| `confirmed` | verdict `CONFIRMED` — the server's reply established the claim |
| `not_confirmed` | verdict `NOT_CONFIRMED` — the server's reply refuted it |
| `inconclusive` | verdict `INCONCLUSIVE` — Enigma could not decide |
| `reported` | status `reported` — no safe automatic check exists; recorded for a reviewer |
| `blocked` | the authorization gate refused; **no request was sent** |
| `reproducible` | the probe was repeated and gave the same result each time |

`confirmed + not_confirmed + inconclusive == total`. `reported` and `blocked`
cut across that: a `reported` finding is always `INCONCLUSIVE`, because Enigma
did not test it.

## Global rates

`confirmation_rate`, `false_positive_rate` and `inconclusive_rate` all divide by
`total`. They describe **the run**, not any particular finder, and they are
deliberately blunt: a run full of untestable findings will show a low
confirmation rate without that saying anything about who reported them.

## Per-source metrics (`summary.by_source`)

Enigma accepts findings from several finders — OpenClaw and the external
instruments — and the interesting question is not how many findings arrived but
**how many survived proof, per source**.

| Key | Meaning |
|---|---|
| `total` | findings this source contributed |
| `confirmed` / `not_confirmed` / `inconclusive` / `reported` / `blocked` | outcome split |
| `decided` | `confirmed + not_confirmed` — findings Enigma actually judged |
| `undecided` | `total − decided` |
| `confirmation_rate` | `confirmed / decided` |
| `refutation_rate` | `not_confirmed / decided` |
| `rate_denominator` | always the literal string `"decided"` |
| `avg_claimed_confidence` | mean of the confidence the *source* asserted |

### Why the denominator is `decided`, not `total`

A `reported` or `INCONCLUSIVE` finding is one Enigma **could not judge** — not
one the finder got wrong. Dividing by `total` would silently convert Enigma's
ignorance into the finder's error, and would punish a source most precisely when
it reports the kinds of issue Enigma has no safe automatic check for (business
logic, authorization flaws). So the rates cover only adjudicated findings, and
`undecided` is published beside them so the omission is visible.

If you want the blunter figure for a paper, it is `confirmed / total` — compute
it from the published counts and say which one you used.

### `avg_claimed_confidence` is not a score

It records what the finder asserted, nothing more. Verification never reads it
(see [`proof.md`](proof.md)), and it cannot move the [RAV](rav.md). It is
published so the gap between claimed and demonstrated can be *measured* rather
than assumed — which is the point of the table:

```
| Source     | Findings | Confirmed | Not confirmed | Undecided | Confirmation rate | Avg. claimed conf. |
|------------|----------|-----------|---------------|-----------|-------------------|--------------------|
| zap        |        1 |         0 |             1 |         0 |                0% |               0.85 |
| nuclei     |        1 |         1 |             0 |         0 |              100% |               0.30 |
| openclaw   |        2 |         1 |             0 |         1 |              100% |               0.68 |
| nmap       |        1 |         0 |             0 |         1 |               n/a |               0.50 |
```

ZAP was 0.85-confident about a header the server was in fact sending. Nuclei was
0.30-confident about one it really was leaking. Claimed confidence and truth are
orthogonal — which is why the verdict comes from the server's reply instead.

`n/a` means the source contributed nothing Enigma could adjudicate; it is not a
zero.

## Reading these honestly

- **A rate over one or two findings is not a rate.** Report the counts.
- **`confirmation_rate` is not precision against ground truth.** It is agreement
  with Enigma's nine observational checks, which cover a narrow slice of what a
  scanner reports. A source scoring 0% may be right about something Enigma
  cannot test.
- **`NOT_CONFIRMED` is evidence about one path at one moment**, not a verdict on
  the finder's competence.
- Every finding carries its own limits — see [`proof.md`](proof.md).

## Where they appear

`summary.by_source` in JSON, a **By source** table in Markdown and a matching
table in the HTML report. Alongside them sit [`summary.rav`](rav.md) and
[`summary.osstmm_modules`](osstmm-modules.md), and the run's integrity record in
[`manifest`](evidence.md#run-manifest-evidencemanifestpy).
