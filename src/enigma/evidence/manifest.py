"""Run manifest — a tamper-evident record of what was verified, and when.

A verdict is only as good as the evidence behind it. This module produces the
paperwork that lets a third party check that the evidence in a report is the
evidence Enigma actually collected:

* a **run header** — framework version, interpreter, target, profile, declared
  instruments, a UTC timestamp, and the digest of the report's ``summary``;
* one **entry per finding** — its verdict, status, source, the SHA-256 digest of
  the sanitized evidence artifact, and the digest of the **published record**
  (the finding as it appears in the report, proof receipt included);
* a **hash chain** — each entry's digest is folded into the previous one, so the
  final ``chain_head`` covers the whole run. Editing, reordering, inserting or
  removing any entry changes ``chain_head``.

Use :func:`verify_report` to check a report end to end — that is the call that
covers the numbers and narrative a reader actually sees. :func:`verify_manifest`
on its own only checks that the manifest is internally consistent.

This is integrity, not authenticity: it proves a report and its evidence were
not altered *relative to each other*, and pins them to a recorded time. It is
not a signature — anyone who can rewrite the whole manifest can recompute the
chain. Store or publish ``chain_head`` separately if that matters.

The digest is taken over the **sanitized** evidence — the same bytes a reader
sees — so verification never requires un-redacted material.
"""

from __future__ import annotations

import hashlib
import json
import platform
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DIGEST_ALGORITHM = "sha256"


def canonical_digest(payload: Any) -> str:
    """SHA-256 over a canonical JSON encoding of ``payload``.

    Keys are sorted and separators fixed so that two structurally equal payloads
    always produce the same digest, whatever order they were built in.
    """

    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _link(previous: str, digest: str) -> str:
    return hashlib.sha256(f"{previous}{digest}".encode("utf-8")).hexdigest()


@dataclass
class ManifestEntry:
    finding_id: str
    source: str
    check: Optional[str]
    verdict: str
    status: str
    evidence_id: Optional[str] = None
    evidence_sha256: Optional[str] = None
    record_sha256: Optional[str] = None
    entry_sha256: str = ""
    chain: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "source": self.source,
            "check": self.check,
            "verdict": self.verdict,
            "status": self.status,
            "evidence_id": self.evidence_id,
            "evidence_sha256": self.evidence_sha256,
            "record_sha256": self.record_sha256,
            "entry_sha256": self.entry_sha256,
            "chain": self.chain,
        }


@dataclass
class RunManifest:
    enigma_version: str = ""
    python_version: str = ""
    generated_at: str = ""
    assessment_id: Optional[str] = None
    target: Optional[str] = None
    profile: Optional[str] = None
    instruments: List[str] = field(default_factory=list)
    total: int = 0
    with_evidence: int = 0
    summary_sha256: Optional[str] = None
    genesis: str = ""
    chain_head: str = ""
    entries: List[ManifestEntry] = field(default_factory=list)

    def header(self) -> Dict[str, Any]:
        """The run header the chain is seeded from.

        Every field the manifest publishes about the run as a whole lives here,
        so anything a reader is shown is covered by ``genesis`` — and therefore
        by ``chain_head``.
        """

        return {
            "enigma_version": self.enigma_version,
            "python_version": self.python_version,
            "generated_at": self.generated_at,
            "assessment_id": self.assessment_id,
            "target": self.target,
            "profile": self.profile,
            "instruments": list(self.instruments),
            "total": self.total,
            "with_evidence": self.with_evidence,
            "summary_sha256": self.summary_sha256,
            "digest_algorithm": DIGEST_ALGORITHM,
        }

    # The header keys, in one place, so build and verify cannot drift apart.
    HEADER_KEYS = (
        "enigma_version",
        "python_version",
        "generated_at",
        "assessment_id",
        "target",
        "profile",
        "instruments",
        "total",
        "with_evidence",
        "summary_sha256",
        "digest_algorithm",
    )

    def to_dict(self) -> dict:
        data = self.header()
        data.update(
            {
                "genesis": self.genesis,
                "chain_head": self.chain_head,
                "entries": [entry.to_dict() for entry in self.entries],
            }
        )
        return data


def _entry_payload(
    result: Any, evidence_digest: Optional[str], record_digest: Optional[str]
) -> Dict[str, Any]:
    finding = result.finding
    return {
        "finding_id": finding.finding_id,
        "source": getattr(finding, "source", None) or "unknown",
        "check": getattr(finding, "check", None),
        "verdict": result.verdict.value,
        "status": result.status,
        "evidence_id": result.evidence.evidence_id if result.evidence else None,
        "evidence_sha256": evidence_digest,
        "record_sha256": record_digest,
    }


def build_manifest(
    results: List[Any],
    assessment: Optional[Any] = None,
    generated_at: Optional[str] = None,
    records: Optional[List[Any]] = None,
    summary: Optional[Any] = None,
) -> RunManifest:
    """Build a hash-chained manifest for one run.

    ``records`` are the published result dicts, in the same order as ``results``
    — pass them (as :func:`enigma.reporting.json.build_report` does) so the chain
    covers the narrative a reader is shown, not just the verdicts. ``summary`` is
    the report's summary; its digest goes into the header.

    ``generated_at`` may be supplied (an ISO-8601 UTC string) to make the
    manifest deterministic; otherwise the current UTC time is stamped.
    """

    from .. import __version__

    if records is not None and len(records) != len(results):
        raise ValueError("records must align one-to-one with results")

    manifest = RunManifest(
        enigma_version=__version__,
        python_version=platform.python_version(),
        generated_at=generated_at or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        total=len(results),
        with_evidence=sum(1 for r in results if r.evidence),
    )
    if summary is not None:
        payload = summary.to_dict() if hasattr(summary, "to_dict") else summary
        manifest.summary_sha256 = canonical_digest(payload)
    if assessment is not None:
        manifest.assessment_id = assessment.assessment_id
        manifest.target = assessment.target.url
        profile = getattr(assessment, "profile", None)
        manifest.profile = getattr(profile, "value", None) or (
            str(profile) if profile is not None else None
        )
        manifest.instruments = list(getattr(assessment, "instruments", ()) or ())

    manifest.genesis = canonical_digest(manifest.header())

    chain = manifest.genesis
    for index, result in enumerate(results):
        evidence_digest = (
            canonical_digest(result.evidence.to_dict()) if result.evidence else None
        )
        record_digest = canonical_digest(records[index]) if records is not None else None
        payload = _entry_payload(result, evidence_digest, record_digest)
        entry_digest = canonical_digest(payload)
        chain = _link(chain, entry_digest)
        manifest.entries.append(
            ManifestEntry(
                finding_id=payload["finding_id"],
                source=payload["source"],
                check=payload["check"],
                verdict=payload["verdict"],
                status=payload["status"],
                evidence_id=payload["evidence_id"],
                evidence_sha256=evidence_digest,
                record_sha256=record_digest,
                entry_sha256=entry_digest,
                chain=chain,
            )
        )

    manifest.chain_head = chain
    return manifest


def verify_manifest(
    manifest: Any,
    evidence_by_id: Optional[Dict[str, Any]] = None,
    report: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """Recompute the chain and report every discrepancy found.

    ``manifest`` may be a :class:`RunManifest` or the plain dict produced by
    :meth:`RunManifest.to_dict` (as read back from a report).

    On its own this checks only that the manifest is **internally** consistent.
    To check a report, pass it — or call :func:`verify_report`, which is the same
    thing with the manifest dug out for you:

    * ``report`` — re-hashes the published ``summary`` and each entry in
      ``results``, so an edited verdict, a doctored proof receipt, a rewritten
      metric or a fabricated finding is caught.
    * ``evidence_by_id`` — a mapping of evidence id to the evidence dict, e.g.
      ``{e.evidence_id: e.to_dict() for e in store.all()}`` — re-hashes the
      stored artifacts and catches evidence edited after the fact.

    Returns an empty list when everything supplied is consistent.
    """

    data = manifest.to_dict() if hasattr(manifest, "to_dict") else dict(manifest)
    problems: List[str] = []

    header = {key: data.get(key) for key in RunManifest.HEADER_KEYS}
    genesis = canonical_digest(header)
    if genesis != data.get("genesis"):
        problems.append("run header does not match the recorded genesis digest")

    entries = data.get("entries") or []
    if data.get("total") != len(entries):
        problems.append(
            "manifest declares {} finding(s) but carries {} entr(ies)".format(
                data.get("total"), len(entries)
            )
        )

    published = (report or {}).get("results")
    if report is not None:
        if data.get("summary_sha256") is None:
            problems.append("manifest does not bind the report summary")
        elif canonical_digest(report.get("summary", {})) != data["summary_sha256"]:
            problems.append("report summary does not match its recorded digest")
        if published is not None and len(published) != len(entries):
            problems.append(
                "report carries {} result(s) but the manifest records {}".format(
                    len(published), len(entries)
                )
            )

    chain = genesis
    chain_broken = False
    for index, entry in enumerate(entries):
        payload = {
            "finding_id": entry.get("finding_id"),
            "source": entry.get("source"),
            "check": entry.get("check"),
            "verdict": entry.get("verdict"),
            "status": entry.get("status"),
            "evidence_id": entry.get("evidence_id"),
            "evidence_sha256": entry.get("evidence_sha256"),
            "record_sha256": entry.get("record_sha256"),
        }
        entry_digest = canonical_digest(payload)
        if entry_digest != entry.get("entry_sha256"):
            problems.append(
                "entry {} ({}) does not match its recorded digest".format(
                    index, entry.get("finding_id")
                )
            )
        chain = _link(chain, entry_digest)
        if chain != entry.get("chain") and not chain_broken:
            # Report only the first break: by construction every later link is
            # then wrong too, and listing them all buries the actual location.
            chain_broken = True
            problems.append(
                "chain breaks at entry {} ({}); every later entry is affected".format(
                    index, entry.get("finding_id")
                )
            )

        if published is not None and index < len(published):
            if entry.get("record_sha256") is None:
                problems.append(
                    "entry {} ({}) does not bind its published record".format(
                        index, entry.get("finding_id")
                    )
                )
            elif canonical_digest(published[index]) != entry["record_sha256"]:
                problems.append(
                    "published record {} ({}) does not match its recorded digest".format(
                        index, entry.get("finding_id")
                    )
                )

        if evidence_by_id is not None and entry.get("evidence_id"):
            stored = evidence_by_id.get(entry["evidence_id"])
            if stored is None:
                problems.append(
                    "evidence {} is referenced but missing".format(entry["evidence_id"])
                )
            elif canonical_digest(stored) != entry.get("evidence_sha256"):
                problems.append(
                    "evidence {} does not match its recorded digest".format(
                        entry["evidence_id"]
                    )
                )

    if chain != data.get("chain_head") and not chain_broken:
        problems.append("chain_head does not match the recomputed chain")

    return problems


def verify_report(
    report: Dict[str, Any], evidence_by_id: Optional[Dict[str, Any]] = None
) -> List[str]:
    """Check a whole report against its own manifest.

    This is the call to reach for: it covers the summary, every published
    finding (proof receipt included) and the hash chain. Supply
    ``evidence_by_id`` as well to re-hash the stored evidence artifacts.

    Returns an empty list when the report is intact.
    """

    manifest = (report or {}).get("manifest")
    if not manifest:
        return ["report carries no manifest"]
    return verify_manifest(manifest, evidence_by_id, report=report)
