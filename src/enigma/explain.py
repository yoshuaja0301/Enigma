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


def build_proof(result: Any, lang: str = "en") -> Dict[str, Any]:
    """Render a verification result into a human-readable proof."""

    check = result.finding.check
    info = explain_check(check, lang)
    observations: List[Dict[str, Any]] = list(getattr(result, "observations", []) or [])
    obs0 = observations[0] if observations else {}
    decisive = (_decisive(check, obs0, lang) if observations
                else translate_reason(result.reason, lang))

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
        "conclusion": info["label"] if proven else None,
        "decisive": decisive,  # retained: same text as `observation`
        "limits": verdict_limits(result.verdict.value, getattr(result, "status", ""), lang),
        "exchanges": exchanges,
        "reproduced": {
            "times": result.probes_run,
            "consistent": result.reproducible,
        },
    }
