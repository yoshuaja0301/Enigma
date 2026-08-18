"""Plain-language explanations and human-readable proof.

The verdicts and the RAV answer *"is it real"* and *"how secure"* — but a
non-specialist still needs to *see* why. This module turns a verification result
into a receipt anyone can read:

* what the check means and why it matters (plain language, en / id),
* the exact request Enigma sent and the exact reply it got back,
* the single decisive fact that proves (or refutes) the finding,
* how many times it reproduced.

Nothing here re-runs anything; it just renders the evidence Enigma already
collected. For a *live* re-proof see ``EnigmaService.prove`` and ``enigma prove``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .findings.model import Verdict

# --------------------------------------------------------------------------- #
# What each check means, in plain language. Two registers: English and a simple
# Indonesian gloss for a lay audience.
# --------------------------------------------------------------------------- #
CHECK_INFO: Dict[str, Dict[str, Dict[str, str]]] = {
    "security_header": {
        "en": {"label": "Missing security header",
               "what": "A protective HTTP header the browser relies on was not sent.",
               "why": "Without it the browser drops a layer of defense against common attacks."},
        "id": {"label": "Header keamanan hilang",
               "what": "Sebuah header pelindung yang diandalkan browser tidak dikirim server.",
               "why": "Tanpa itu, browser kehilangan satu lapis pertahanan terhadap serangan umum."},
    },
    "reflection": {
        "en": {"label": "Input reflected in the page",
               "what": "Text we put in the URL came back inside the page unchanged.",
               "why": "Reflected input is the first ingredient of cross-site scripting (XSS)."},
        "id": {"label": "Input terpantul di halaman",
               "what": "Teks yang kami taruh di URL muncul kembali apa adanya di halaman.",
               "why": "Input yang terpantul adalah bahan awal serangan XSS."},
    },
    "http_method": {
        "en": {"label": "Risky HTTP method enabled",
               "what": "The server advertises an HTTP method that is usually unnecessary.",
               "why": "Methods like TRACE can help an attacker read data they shouldn't."},
        "id": {"label": "Metode HTTP berisiko aktif",
               "what": "Server mengumumkan sebuah metode HTTP yang biasanya tidak diperlukan.",
               "why": "Metode seperti TRACE bisa membantu penyerang membaca data terlarang."},
    },
    "cookie_flags": {
        "en": {"label": "Insecure cookie",
               "what": "A cookie was set without a protective flag (Secure/HttpOnly/SameSite).",
               "why": "Such cookies can be stolen or misused to hijack a user's session."},
        "id": {"label": "Cookie tidak aman",
               "what": "Cookie dipasang tanpa flag pelindung (Secure/HttpOnly/SameSite).",
               "why": "Cookie seperti ini bisa dicuri atau disalahgunakan untuk membajak sesi."},
    },
    "cors": {
        "en": {"label": "Permissive CORS",
               "what": "The server accepts requests from any website we claimed to be.",
               "why": "This can let a malicious site read data on behalf of your users."},
        "id": {"label": "CORS terlalu longgar",
               "what": "Server menerima permintaan dari website mana pun yang kami akui.",
               "why": "Ini bisa membuat situs jahat membaca data atas nama pengguna Anda."},
    },
    "tls_redirect": {
        "en": {"label": "HTTPS not enforced",
               "what": "The site served plain HTTP without redirecting to HTTPS.",
               "why": "Traffic over plain HTTP can be read or altered on the network."},
        "id": {"label": "HTTPS tidak dipaksakan",
               "what": "Situs melayani HTTP biasa tanpa mengalihkan ke HTTPS.",
               "why": "Lalu lintas HTTP biasa bisa dibaca atau diubah di jaringan."},
    },
    "clickjacking": {
        "en": {"label": "Page can be framed (clickjacking)",
               "what": "The page can be embedded inside another site in a frame.",
               "why": "An attacker can overlay it to trick users into clicking things."},
        "id": {"label": "Halaman bisa di-frame (clickjacking)",
               "what": "Halaman bisa disematkan ke dalam situs lain lewat frame.",
               "why": "Penyerang bisa menumpanginya untuk menipu pengguna agar salah klik."},
    },
    "directory_listing": {
        "en": {"label": "Directory listing exposed",
               "what": "The server returned a browsable list of files in a folder.",
               "why": "It can reveal files that were never meant to be public."},
        "id": {"label": "Daftar isi folder terbuka",
               "what": "Server menampilkan daftar berkas dalam sebuah folder.",
               "why": "Ini bisa membocorkan berkas yang tidak dimaksudkan untuk publik."},
    },
    "server_version": {
        "en": {"label": "Server version disclosed",
               "what": "Response headers reveal the exact server/technology version.",
               "why": "It tells an attacker which known exploits to try first."},
        "id": {"label": "Versi server bocor",
               "what": "Header respons membocorkan versi server/teknologi yang tepat.",
               "why": "Ini memberi tahu penyerang eksploit lama mana yang layak dicoba."},
    },
    "open_redirect": {
        "en": {"label": "Open redirect",
               "what": "A URL parameter sent the browser on to an outside website we chose.",
               "why": "Attackers abuse it to make a trusted link land on a phishing page."},
        "id": {"label": "Open redirect",
               "what": "Sebuah parameter URL mengarahkan browser ke situs luar pilihan kami.",
               "why": "Penyerang menyalahgunakannya agar tautan tepercaya berujung di halaman phishing."},
    },
}

_UNKNOWN = {
    "en": {"label": "Reported finding",
           "what": "OpenClaw reported this, but there is no safe automatic check for it.",
           "why": "It needs a human to verify — Enigma did not prove or disprove it."},
    "id": {"label": "Temuan yang dilaporkan",
           "what": "OpenClaw melaporkannya, tapi belum ada cek otomatis yang aman.",
           "why": "Perlu diperiksa manusia — Enigma belum membuktikan atau menyanggahnya."},
}


def explain_check(check: Optional[str], lang: str = "en") -> Dict[str, str]:
    info = CHECK_INFO.get(check or "", _UNKNOWN)
    return info.get(lang, info["en"])


# --------------------------------------------------------------------------- #
# The decisive fact, stated plainly from what was actually observed.
# --------------------------------------------------------------------------- #
def _decisive_key(check: Optional[str], obs: Dict[str, Any]) -> Tuple[str, Dict[str, str]]:
    """Pick WHICH statement the observation supports, plus its parameters.

    What the server did is decided here, once, from the observation alone. The
    wording per language lives in `_DECISIVE`. Keeping them apart is the point:
    adding a language must never be able to change which fact gets stated.
    """
    if check == "security_header":
        h = obs.get("header", "the header")
        state = "present" if obs.get("present") else "absent"
        return f"security_header.{state}", {"header": h}
    if check == "reflection":
        return ("reflection." + ("yes" if obs.get("marker_reflected") else "no")), {}
    if check == "http_method":
        m = obs.get("method", "the method")
        adv = obs.get("advertised") or []
        if m in adv:
            return "http_method.advertised", {"method": m, "advertised": ", ".join(adv)}
        return "http_method.absent", {"method": m}
    if check == "cookie_flags":
        flag = obs.get("flag", "the flag")
        missing = obs.get("cookies_missing_flag") or []
        if missing:
            return "cookie_flags.missing", {"cookies": ", ".join(missing), "flag": flag}
        return "cookie_flags.all_present", {"flag": flag}
    if check == "cors":
        if obs.get("credentialed_reflection"):
            return "cors.credentialed", {}
        if obs.get("reflects_origin"):
            return "cors.reflects", {}
        if obs.get("wildcard"):
            return "cors.wildcard", {}
        return "cors.none", {}
    if check == "tls_redirect":
        state = "redirects" if obs.get("redirects_to_https") else "plain"
        return f"tls_redirect.{state}", {}
    if check == "clickjacking":
        state = "frameable" if obs.get("frameable") else "protected"
        return f"clickjacking.{state}", {}
    if check == "directory_listing":
        if obs.get("listing_detected"):
            return "directory_listing.yes", {"signature": str(obs.get("signature"))}
        return "directory_listing.no", {}
    if check == "server_version":
        disclosures = obs.get("disclosures") or {}
        if disclosures:
            joined = "; ".join(f"{k}: {v}" for k, v in disclosures.items())
            return "server_version.disclosed", {"disclosures": joined}
        return "server_version.none", {}
    if check == "open_redirect":
        if obs.get("redirects_offsite"):
            return "open_redirect.yes", {"location": str(obs.get("location"))}
        return "open_redirect.no", {}
    return "fallback", {}


# Wording only. Every entry states the same fact in both registers; none of them
# may hedge a fact the other asserts.
_DECISIVE = {
    "security_header.absent": {
        "en": "The reply did NOT include the '{header}' header.",
        "id": "Jawaban server TIDAK memuat header '{header}'."},
    "security_header.present": {
        "en": "The reply DID include '{header}'.",
        "id": "Jawaban server MEMUAT '{header}'."},
    "reflection.yes": {
        "en": "The exact text we sent came back inside the page.",
        "id": "Teks persis yang kami kirim muncul kembali di dalam halaman."},
    "reflection.no": {
        "en": "The text we sent did not appear in the page.",
        "id": "Teks yang kami kirim tidak muncul di halaman."},
    "http_method.advertised": {
        "en": "The server's 'Allow' list advertises {method}: {advertised}.",
        "id": "Daftar 'Allow' server mencantumkan {method}: {advertised}."},
    "http_method.absent": {
        "en": "The server's 'Allow' list does not include {method}.",
        "id": "Daftar 'Allow' server tidak mencantumkan {method}."},
    "cookie_flags.missing": {
        "en": "Cookie(s) {cookies} were set without the {flag} flag.",
        "id": "Cookie {cookies} diset tanpa flag {flag}."},
    "cookie_flags.all_present": {
        "en": "Every cookie carried the {flag} flag.",
        "id": "Semua cookie membawa flag {flag}."},
    "cors.credentialed": {
        "en": "The server echoed our Origin AND allows credentials — the dangerous combination.",
        "id": "Server memantulkan Origin kami DAN mengizinkan kredensial — kombinasi yang berbahaya."},
    "cors.reflects": {
        "en": "The server echoed back the arbitrary Origin we sent.",
        "id": "Server memantulkan kembali Origin sembarang yang kami kirim."},
    "cors.wildcard": {
        "en": "The server allows any origin ('*').",
        "id": "Server mengizinkan origin mana pun ('*')."},
    "cors.none": {
        "en": "The server did not reflect our Origin.",
        "id": "Server tidak memantulkan Origin kami."},
    "tls_redirect.plain": {
        "en": "Plain HTTP was served without redirecting to HTTPS.",
        "id": "HTTP biasa dilayani tanpa dialihkan ke HTTPS."},
    "tls_redirect.redirects": {
        "en": "HTTP was redirected to HTTPS.",
        "id": "HTTP dialihkan ke HTTPS."},
    "clickjacking.frameable": {
        "en": "The page can be framed (no X-Frame-Options and no CSP frame-ancestors).",
        "id": "Halaman bisa di-frame (tanpa X-Frame-Options dan tanpa CSP frame-ancestors)."},
    "clickjacking.protected": {
        "en": "The page is protected against framing.",
        "id": "Halaman terlindungi dari framing."},
    "directory_listing.yes": {
        "en": "The reply looked like a directory index (matched '{signature}').",
        "id": "Jawaban server tampak seperti indeks direktori (cocok dengan '{signature}')."},
    "directory_listing.no": {
        "en": "The reply was not a directory listing.",
        "id": "Jawaban server bukan daftar isi direktori."},
    "server_version.disclosed": {
        "en": "The server disclosed: {disclosures}",
        "id": "Server menyingkapkan: {disclosures}"},
    "server_version.none": {
        "en": "No server/version banner was disclosed.",
        "id": "Tidak ada banner server/versi yang disingkapkan."},
    "open_redirect.yes": {
        "en": "The server redirected to the external address we supplied ({location}).",
        "id": "Server mengalihkan ke alamat eksternal yang kami berikan ({location})."},
    "open_redirect.no": {
        "en": "The redirect parameter did not send us to an external site.",
        "id": "Parameter pengalihan tidak mengarahkan kami ke situs eksternal."},
    "fallback": {
        "en": "See the observations for details.",
        "id": "Lihat bagian observasi untuk detailnya."},
}


def _decisive(check: Optional[str], obs: Dict[str, Any], lang: str = "en") -> str:
    key, params = _decisive_key(check, obs)
    wording = _DECISIVE[key]
    return wording.get(lang, wording["en"]).format(**params)


# The engine states its `reason` once, in English, because it is a stable field
# that reports and tests read. Translating it is this layer's job; an unknown
# reason passes through untouched rather than being silently dropped.
_REASONS = {
    "condition consistently observed across probes":
        "kondisi teramati konsisten di seluruh probe",
    "expected condition was not reproduced":
        "kondisi yang diharapkan tidak terulang",
    "inconsistent results across probes":
        "hasil tidak konsisten antar probe",
    "no automatic check for this finding type; reported for review":
        "tidak ada pemeriksaan otomatis untuk jenis temuan ini; dicatat untuk ditinjau",
    "no successful probes": "tidak ada probe yang berhasil",
}


def translate_reason(reason: str, lang: str = "en") -> str:
    """Render an engine reason in `lang`, passing unknown text through."""
    if lang == "en" or not reason:
        return reason
    if reason in _REASONS:
        return _REASONS[reason]
    if reason.startswith("all probes failed: "):
        return "semua probe gagal: " + reason[len("all probes failed: "):]
    if reason.startswith("procedure '") and reason.endswith("' requires additional parameters"):
        name = reason[len("procedure '"):-len("' requires additional parameters")]
        return f"prosedur '{name}' butuh parameter tambahan"
    if reason.startswith("ASSESSMENT BLOCKED"):
        return reason.replace("ASSESSMENT BLOCKED", "ASESMEN DIBLOKIR", 1)
    return reason


_HOW = {
    "en": "We only sent the request shown below and read the reply — no attack, no data changed.",
    "id": "Kami hanya mengirim permintaan di bawah ini lalu membaca jawabannya — tanpa serangan, tanpa mengubah data.",
}

# --------------------------------------------------------------------------- #
# Limits of what a verdict establishes.
#
# Enigma's *observations* are facts — they are bytes the server actually sent.
# Its *conclusions* are claims resting on those facts. Stating the boundary is a
# requirement of the framework, not a disclaimer: a reader must be able to
# disagree with a conclusion while still trusting the observation.
# --------------------------------------------------------------------------- #
_LIMITS = {
    "CONFIRMED": {
        "en": [
            "Establishes that the condition was present in the server's own reply, repeated consistently.",
            "Does NOT establish exploitability or business impact — that requires human judgement.",
            "Observed at one moment from one vantage point; caching, load balancing or a WAF may differ elsewhere.",
        ],
        "id": [
            "Membuktikan kondisi itu ADA pada jawaban server sendiri, dan berulang konsisten.",
            "TIDAK membuktikan bisa dieksploitasi atau seberapa besar dampaknya — itu perlu penilaian manusia.",
            "Diamati pada satu waktu dari satu titik; cache, load balancer, atau WAF bisa berbeda di tempat lain.",
        ],
    },
    "NOT_CONFIRMED": {
        "en": [
            "Means THIS check did not reproduce the condition — it does NOT mean the target is safe.",
            "Absence of evidence here is not evidence of absence elsewhere (other paths, states or times).",
        ],
        "id": [
            "Artinya cek INI tidak menemukan kondisi tersebut — BUKAN berarti target aman.",
            "Tidak ditemukan di sini bukan berarti tidak ada di tempat lain (jalur, kondisi, atau waktu lain).",
        ],
    },
    "INCONCLUSIVE": {
        "en": [
            "Enigma neither proved nor disproved this — treat it as an open question, not a result.",
            "It carries no weight in the security score (RAV); only verified observations do.",
        ],
        "id": [
            "Enigma tidak membuktikan maupun menyanggah ini — anggap pertanyaan terbuka, bukan hasil.",
            "Tidak ikut menentukan skor keamanan (RAV); hanya observasi terverifikasi yang dihitung.",
        ],
    },
}

_REPORTED_LIMIT = {
    "en": "This is OpenClaw's hypothesis only — Enigma performed no check on it. It is not evidence.",
    "id": "Ini murni dugaan OpenClaw — Enigma tidak melakukan pengecekan apa pun. Bukan bukti.",
}


def verdict_limits(verdict: str, status: str = "", lang: str = "en") -> List[str]:
    """What this verdict does — and does not — establish."""

    entry = _LIMITS.get(verdict, _LIMITS["INCONCLUSIVE"])
    limits = list(entry.get(lang, entry["en"]))
    if status == "reported":
        limits.insert(0, _REPORTED_LIMIT.get(lang, _REPORTED_LIMIT["en"]))
    return limits


# Labels for the surfaces that render a proof. Kept here beside the rest of the
# translations so a new language is one file to edit, not a hunt through the CLI.
_UI = {
    "en": {
        "what": "What it means", "why": "Why it matters", "how": "How we checked",
        "proof": "Proof (what we sent and got back):",
        "observed": ">> OBSERVED (fact):",
        "repeated": "Repeated {times} time(s); {consistency}.",
        "consistent": "same result each time", "varied": "results varied",
        # 0 probes is neither consistent nor varied — say what happened instead.
        "not_probed": "Not probed — nothing was sent for this finding.",
        "limits": "Limits of this verdict:",
        "headline_proven": "Proven", "headline_not_confirmed": "Not confirmed",
        "CONFIRMED": "PROVEN", "NOT_CONFIRMED": "not a problem",
        "INCONCLUSIVE": "unproven",
    },
    "id": {
        "what": "Artinya", "why": "Kenapa penting", "how": "Cara kami cek",
        "proof": "Bukti (yang kami kirim dan yang dibalas):",
        "observed": ">> DIAMATI (fakta):",
        "repeated": "Diulang {times} kali; {consistency}.",
        "consistent": "hasilnya sama tiap kali", "varied": "hasilnya berbeda-beda",
        "not_probed": "Tidak diprobe — tidak ada permintaan yang dikirim untuk temuan ini.",
        "limits": "Batas dari putusan ini:",
        "headline_proven": "Terbukti", "headline_not_confirmed": "Tidak terbukti",
        "CONFIRMED": "TERBUKTI", "NOT_CONFIRMED": "bukan masalah",
        "INCONCLUSIVE": "belum terbukti",
    },
}


def ui_labels(lang: str = "en") -> Dict[str, str]:
    """Labels for rendering a proof, falling back to English per key."""
    merged = dict(_UI["en"])
    merged.update(_UI.get(lang, {}))
    return merged


# Chrome for the rendered reports (HTML page, Markdown). Kept here with the rest
# of the translations so a new language stays one file to edit.
#
# OSSTMM's own vocabulary is deliberately NOT translated: channel and control
# names, the 17 module names and the RAV grades are terms of art that tie a
# report back to the methodology. Rendering them in another language would break
# that link for the reader who goes looking.
_REPORT = {
    "en": {
        "report_title": "Enigma Assessment Report",
        "dashboard_title": "Enigma Dashboard",
        "dashboard_sub": "Assessment dashboard",
        "summary": "Summary", "findings": "Findings", "confirmed": "Confirmed",
        "not_confirmed": "Not confirmed", "inconclusive": "Inconclusive",
        "reported": "Reported", "blocked": "Blocked", "reproducible": "Reproducible",
        "confirmation_rate": "Confirmation rate", "fp_rate": "False-positive rate",
        "target": "Target", "procedure": "Procedure", "probes_run": "Probes run",
        "yes": "yes", "no": "no", "na": "n/a",
        "ai_confidence": "AI confidence", "enigma_confidence": "Enigma confidence",
        "evidence": "Evidence", "raw_observations": "Raw observations",
        "what_this_means": "What this means", "why_it_matters": "Why it matters",
        "proof_heading": "Proof — what we sent and got back",
        "response_headers": "response headers",
        "repeated": "Repeated {times} time(s) — {consistency}.",
        "consistent": "same result each time", "varied": "results varied",
        "not_probed": "Not probed — nothing was sent for this finding.",
        "limits_summary": "What this verdict does and does not establish",
        "prove_btn": "▶ Prove it live",
        "proving": "Proving…",
        "live_recheck": "Live re-check just now:",
        "repeated_now": "Repeated {times} time(s) just now.",
        "by_source": "By source",
        "by_source_note": ("Rates are over <strong>decided</strong> findings "
                           "(confirmed + not confirmed). Findings Enigma could not judge are "
                           "counted as undecided, never held against the finder."),
        "source": "Source", "undecided": "Undecided",
        "avg_claimed": "Avg. claimed conf.",
        "rav_heading": "OSSTMM RAV — Risk Assessment Value",
        "actual_security": "Actual Security", "deficit": "deficit",
        "true_protection": "True Protection", "true_coverage": "True Coverage",
        "porosity": "Porosity (OpSec)", "controls_evidenced": "Controls evidenced",
        "limitations_verified": "Limitations (verified)",
        "excluded_unverified": "Excluded (unverified)",
        "missing_control": "missing control",
        "rav_note": ("Computed from <strong>verified observations only</strong>: "
                     "CONFIRMED findings become limitations, NOT_CONFIRMED findings evidence "
                     "a control, and unverified findings are excluded and counted separately."),
        "modules_heading": "OSSTMM module coverage",
        "modules_covered": "Modules covered",
        "methodology_coverage": "Methodology coverage",
        "instruments": "Instruments",
        "phase": "Phase", "module": "Module", "covered": "Covered", "by": "By",
        "coverage_heading": "OSSTMM coverage",
        "manifest_heading": "Run manifest",
        "generated_at": "Generated at (UTC)", "enigma_version": "Enigma version",
        "python": "Python", "assessment": "Assessment", "profile": "Profile",
        "findings_recorded": "Findings recorded", "with_evidence": "with evidence",
        "digest": "Digest", "chain_head": "Chain head",
        "manifest_note": ("The chain covers the summary, every finding as published on this "
                          "page, and each evidence artifact: alter any of them and the chain "
                          "head no longer matches. Re-check with "
                          "<code>enigma.evidence.verify_report</code>. This shows the report "
                          "was not altered after the fact — it is not a signature."),
        "no_findings": "No findings were assessed.",
        "no_assessments": ("No assessments have been verified yet. POST an assessment to "
                           "<span class=\"mono\">/verify</span> to get started."),
        "total": "Total", "report": "Report", "view_html": "View HTML",
        "footer": ("Generated by <strong>Enigma</strong> — evidence-based verification for "
                   "authorized web vulnerability assessment. Verdicts reflect controlled, "
                   "non-destructive verification; evidence is sanitized."),
        "dashboard_footer": "Enigma dashboard · served by",
        "verdict": "Verdict", "reason": "Reason",
        "verification_confidence": "Verification confidence",
        # Markdown-only wording (plain text, no HTML tags).
        "field": "Field", "value": "Value", "metric": "Metric",
        "visibility": "visibility", "access": "access", "trust": "trust", "of": "of",
        "security_deficit": "Security deficit",
        "limitation_categories": "Limitation categories",
        "modules_covered_md": "modules covered",
        "findings_assessed": "Findings assessed",
        "reported_not_auto": "Reported (not auto-verified)",
        "by_source_note_md": ("Rates are over **decided** findings (CONFIRMED + NOT_CONFIRMED). "
                              "Findings Enigma could not judge are counted as *undecided*, "
                              "never held against the finder."),
        "manifest_note_md": ("The chain covers the summary above, every finding as published "
                             "here, and each evidence artifact: alter any of them and "
                             "`chain head` no longer matches. Re-check with "
                             "`enigma.evidence.verify_report(report)`."),
        "rav_note_md": ("Computed from **verified observations only** — `CONFIRMED` findings "
                        "become limitations, `NOT_CONFIRMED` findings evidence a control, and "
                        "unverified (`reported` / `INCONCLUSIVE`) findings are excluded and "
                        "counted separately."),
    },
    "id": {
        "report_title": "Laporan Asesmen Enigma",
        "dashboard_title": "Dasbor Enigma",
        "dashboard_sub": "Dasbor asesmen",
        "summary": "Ringkasan", "findings": "Temuan", "confirmed": "Terbukti",
        "not_confirmed": "Tidak terbukti", "inconclusive": "Belum terbukti",
        "reported": "Dilaporkan", "blocked": "Diblokir", "reproducible": "Dapat diulang",
        "confirmation_rate": "Tingkat pembuktian", "fp_rate": "Tingkat positif palsu",
        "target": "Target", "procedure": "Prosedur", "probes_run": "Probe dijalankan",
        "yes": "ya", "no": "tidak", "na": "t/a",
        "ai_confidence": "Keyakinan AI", "enigma_confidence": "Keyakinan Enigma",
        "evidence": "Bukti", "raw_observations": "Observasi mentah",
        "what_this_means": "Artinya", "why_it_matters": "Kenapa penting",
        "proof_heading": "Bukti — yang kami kirim dan yang dibalas",
        "response_headers": "header respons",
        "repeated": "Diulang {times} kali — {consistency}.",
        "consistent": "hasilnya sama tiap kali", "varied": "hasilnya berbeda-beda",
        "not_probed": "Tidak diprobe — tidak ada permintaan yang dikirim untuk temuan ini.",
        "limits_summary": "Yang dibuktikan dan tidak dibuktikan putusan ini",
        "prove_btn": "▶ Buktikan langsung",
        "proving": "Membuktikan…",
        "live_recheck": "Cek ulang langsung barusan:",
        "repeated_now": "Diulang {times} kali barusan.",
        "by_source": "Per sumber",
        "by_source_note": ("Tingkat dihitung atas temuan yang <strong>diputus</strong> "
                           "(terbukti + tidak terbukti). Temuan yang tidak bisa dinilai Enigma "
                           "dihitung sebagai belum diputus, tidak pernah dibebankan ke penemu."),
        "source": "Sumber", "undecided": "Belum diputus",
        "avg_claimed": "Rata-rata klaim",
        "rav_heading": "OSSTMM RAV — Risk Assessment Value",
        "actual_security": "Keamanan Aktual", "deficit": "defisit",
        "true_protection": "True Protection", "true_coverage": "True Coverage",
        "porosity": "Porositas (OpSec)", "controls_evidenced": "Kontrol terbukti",
        "limitations_verified": "Limitation (terverifikasi)",
        "excluded_unverified": "Dikecualikan (tak terverifikasi)",
        "missing_control": "kontrol hilang",
        "rav_note": ("Dihitung <strong>hanya dari observasi terverifikasi</strong>: temuan "
                     "CONFIRMED menjadi limitation, temuan NOT_CONFIRMED membuktikan sebuah "
                     "kontrol, dan temuan tak terverifikasi dikecualikan serta dihitung "
                     "terpisah."),
        "modules_heading": "Cakupan modul OSSTMM",
        "modules_covered": "Modul tercakup",
        "methodology_coverage": "Cakupan metodologi",
        "instruments": "Instrumen",
        "phase": "Fase", "module": "Modul", "covered": "Tercakup", "by": "Oleh",
        "coverage_heading": "Cakupan OSSTMM",
        "manifest_heading": "Manifest run",
        "generated_at": "Dibuat pada (UTC)", "enigma_version": "Versi Enigma",
        "python": "Python", "assessment": "Asesmen", "profile": "Profil",
        "findings_recorded": "Temuan tercatat", "with_evidence": "dengan bukti",
        "digest": "Digest", "chain_head": "Kepala rantai",
        "manifest_note": ("Rantai ini mencakup ringkasan, setiap temuan sebagaimana "
                          "diterbitkan di halaman ini, dan tiap artefak bukti: ubah salah "
                          "satunya dan kepala rantai tidak lagi cocok. Periksa ulang dengan "
                          "<code>enigma.evidence.verify_report</code>. Ini menunjukkan laporan "
                          "tidak diubah setelah dibuat — ini bukan tanda tangan digital."),
        "no_findings": "Tidak ada temuan yang diasesmen.",
        "no_assessments": ("Belum ada asesmen yang diverifikasi. Kirim POST asesmen ke "
                           "<span class=\"mono\">/verify</span> untuk memulai."),
        "total": "Total", "report": "Laporan", "view_html": "Lihat HTML",
        "footer": ("Dibuat oleh <strong>Enigma</strong> — verifikasi berbasis bukti untuk "
                   "asesmen kerentanan web yang berizin. Putusan mencerminkan verifikasi "
                   "terkendali dan non-destruktif; bukti telah disanitasi."),
        "dashboard_footer": "Dasbor Enigma · disajikan oleh",
        "verdict": "Putusan", "reason": "Alasan",
        "verification_confidence": "Keyakinan verifikasi",
        "field": "Kolom", "value": "Nilai", "metric": "Metrik",
        "visibility": "visibility", "access": "access", "trust": "trust", "of": "dari",
        "security_deficit": "Defisit keamanan",
        "limitation_categories": "Kategori limitation",
        "modules_covered_md": "modul tercakup",
        "findings_assessed": "Temuan diasesmen",
        "reported_not_auto": "Dilaporkan (tidak diverifikasi otomatis)",
        "by_source_note_md": ("Tingkat dihitung atas temuan yang **diputus** (CONFIRMED + "
                              "NOT_CONFIRMED). Temuan yang tidak bisa dinilai Enigma dihitung "
                              "sebagai *belum diputus*, tidak pernah dibebankan ke penemu."),
        "manifest_note_md": ("Rantai ini mencakup ringkasan di atas, setiap temuan sebagaimana "
                             "diterbitkan di sini, dan tiap artefak bukti: ubah salah satunya "
                             "dan `chain head` tidak lagi cocok. Periksa ulang dengan "
                             "`enigma.evidence.verify_report(report)`."),
        "rav_note_md": ("Dihitung **hanya dari observasi terverifikasi** — temuan `CONFIRMED` "
                        "menjadi limitation, temuan `NOT_CONFIRMED` membuktikan sebuah kontrol, "
                        "dan temuan tak terverifikasi (`reported` / `INCONCLUSIVE`) "
                        "dikecualikan serta dihitung terpisah."),
    },
}


def report_labels(lang: str = "en") -> Dict[str, str]:
    """Chrome for a rendered report, falling back to English per key."""
    merged = dict(_REPORT["en"])
    merged.update(_REPORT.get(lang, {}))
    return merged


def build_proof(result: Any, lang: str = "en") -> Dict[str, Any]:
    """Render a verification result into a human-readable proof."""

    check = result.finding.check
    info = explain_check(check, lang)
    observations: List[Dict[str, Any]] = list(getattr(result, "observations", []) or [])
    obs0 = observations[0] if observations else {}
    if observations:
        obs_key, obs_params = _decisive_key(check, obs0)
        decisive = _decisive(check, obs0, lang)
    else:
        obs_key, obs_params = "", {}
        decisive = translate_reason(result.reason, lang)

    exchanges = []
    evidence = getattr(result, "evidence", None)
    for ex in (evidence.exchanges if evidence else []):
        req = ex.get("request", {})
        resp = ex.get("response", {})
        exchanges.append(
            {
                "request": f"{req.get('method', 'GET')} {req.get('url', '')}",
                "response_status": resp.get("status"),
                "response_headers": resp.get("headers", {}),
                "body_excerpt": resp.get("body_excerpt", ""),
            }
        )

    proven = result.verdict is Verdict.CONFIRMED
    ui = ui_labels(lang)
    if proven:
        headline = f"{ui['headline_proven']}: {decisive}"
    elif result.verdict is Verdict.NOT_CONFIRMED:
        headline = f"{ui['headline_not_confirmed']}: {decisive}"
    else:
        headline = info["what"]

    return {
        "label": info["label"],
        "what": info["what"],
        "why": info["why"],
        "how": _HOW.get(lang, _HOW["en"]),
        "proven": proven,
        "verdict": result.verdict.value,
        "headline": headline,
        # `observation` is a fact about what the server sent; `conclusion` is the
        # claim Enigma draws from it. They are reported separately so a reader can
        # accept the first while questioning the second.
        "observation": decisive,
        # The fact, as a key plus parameters. A stored report can therefore be
        # re-rendered in another language without re-running anything — see
        # `localize_proof`. The prose above stays the canonical English record.
        "observation_key": obs_key,
        "observation_params": obs_params,
        "conclusion": info["label"] if proven else None,
        "decisive": decisive,  # retained: same text as `observation`
        "limits": verdict_limits(result.verdict.value, getattr(result, "status", ""), lang),
        "exchanges": exchanges,
        "reproduced": {
            "times": result.probes_run,
            "consistent": result.reproducible,
        },
    }


def localize_proof(
    proof: Dict[str, Any],
    check: Optional[str],
    verdict: str,
    status: str = "",
    lang: str = "en",
) -> Dict[str, Any]:
    """Restate a stored proof in `lang`, without re-running anything.

    A report is stored once, in English. Serving it in another language must not
    mean re-probing the target — everything a reader sees is derivable from the
    check name, the verdict and the observation key the proof already carries.
    Anything not derivable (an engine reason with no translation) is left as it
    was rather than guessed at.
    """
    if lang == "en" or not proof:
        return proof

    info = explain_check(check, lang)
    ui = ui_labels(lang)
    out = dict(proof)
    out["label"] = info["label"]
    out["what"] = info["what"]
    out["why"] = info["why"]
    out["how"] = _HOW.get(lang, _HOW["en"])
    out["limits"] = verdict_limits(verdict, status, lang)

    key = proof.get("observation_key")
    if key and key in _DECISIVE:
        wording = _DECISIVE[key]
        decisive = wording.get(lang, wording["en"]).format(**(proof.get("observation_params") or {}))
    else:
        decisive = translate_reason(str(proof.get("observation", "")), lang)
    out["observation"] = out["decisive"] = decisive

    if verdict == "CONFIRMED":
        out["headline"] = f"{ui['headline_proven']}: {decisive}"
    elif verdict == "NOT_CONFIRMED":
        out["headline"] = f"{ui['headline_not_confirmed']}: {decisive}"
    else:
        out["headline"] = info["what"]
    out["conclusion"] = info["label"] if verdict == "CONFIRMED" else None
    return out
