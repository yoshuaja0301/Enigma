# Proof — showing it's real, not an AI guess

A verdict and a number are not enough for a non-specialist. Enigma turns every
result into a **receipt anyone can read**, and offers a **live "prove it"
action** that re-runs the check against the real target on demand.

## 1. The receipt (in every report)

For each finding, the report now shows, in plain language:

- **What this means** — the finding in one sentence.
- **Why it matters** — the risk, without jargon.
- **Proof — what we sent and got back** — the *exact* request Enigma sent and
  the server's *exact* reply, then the single **decisive line** that proves (or
  refutes) it, and how many times it reproduced.

This is not a re-description of the verdict — it is the raw evidence Enigma
already collected, sanitized, laid out so a reader can check it themselves.

Example (`enigma prove --lang id`):

```
F-4  [PROVEN]  Versi server bocor
  What it means : Header respons membocorkan versi server/teknologi yang tepat.
  Why it matters: Ini memberi tahu penyerang eksploit lama mana yang layak dicoba.
  How we checked: Kami hanya mengirim permintaan di bawah ini lalu membaca jawabannya
                  — tanpa serangan, tanpa mengubah data.
  Proof (what we sent and got back):
    → GET http://target/
    ← HTTP 200
  >> The server disclosed: Server: nginx/1.18.0
  Repeated 2 time(s); same result each time.
```

Plain language comes in two registers, `en` and `id`
(`explain.explain_check(check, lang)`), so a lay audience can read it in
Indonesian.

## 2. The "Prove it live" action

Because a stored verdict could always be doubted ("maybe it was cached, maybe the
AI made it up"), Enigma can **re-run a single finding on demand** and show the
fresh request/response:

- **CLI:** `enigma prove --assessment A.json --findings F.json [--id F-1] [--lang id]`
  runs the check and prints the proof transcript.
- **Dashboard:** the report served at `GET /report/{id}` is interactive — each
  finding has a **▶ Prove it live** button that calls `POST /prove`
  (`{assessment_id, finding_id}`), re-verifies against the real target *right
  now*, and shows the new evidence inline.
- **Service / API:** `EnigmaService.prove(assessment_id, finding_id)` →
  `{finding_id, result, proof}`.

The live re-check goes through the **same authorization-first gate** and the same
non-destructive procedures, so "prove it" can never do anything the original
assessment couldn't.

## What the proof is (and isn't)

- It **is** the actual, reproducible HTTP exchange that demonstrates the
  condition — the thing that separates a *confirmed finding* from an *AI guess*.
- It is **not** an exploit. Enigma proves a weakness by *observing* it, never by
  attacking. For finding types that could only be proven by attacking (SQLi,
  IDOR, …) there is deliberately no automatic proof — they stay `reported` for a
  human, and the report says so.

See also [verification.md](verification.md) and [rav.md](rav.md).
