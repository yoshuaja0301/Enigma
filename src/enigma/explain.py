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

from typing import Any, Dict, List, Optional

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
def _decisive(check: Optional[str], obs: Dict[str, Any]) -> str:
    if check == "security_header":
        h = obs.get("header", "the header")
        return (f"The reply did NOT include the '{h}' header."
                if not obs.get("present") else f"The reply DID include '{h}'.")
    if check == "reflection":
        return ("The exact text we sent came back inside the page."
                if obs.get("marker_reflected") else "The text we sent did not appear in the page.")
    if check == "http_method":
        m = obs.get("method", "the method")
        adv = obs.get("advertised") or []
        return (f"The server's 'Allow' list advertises {m}: {', '.join(adv)}."
                if m in adv else f"The server's 'Allow' list does not include {m}.")
    if check == "cookie_flags":
        flag = obs.get("flag", "the flag")
        missing = obs.get("cookies_missing_flag") or []
        return (f"Cookie(s) {', '.join(missing)} were set without the {flag} flag."
                if missing else f"Every cookie carried the {flag} flag.")
    if check == "cors":
        if obs.get("credentialed_reflection"):
            return "The server echoed our Origin AND allows credentials — the dangerous combination."
        if obs.get("reflects_origin"):
            return "The server echoed back the arbitrary Origin we sent."
        if obs.get("wildcard"):
            return "The server allows any origin ('*')."
        return "The server did not reflect our Origin."
    if check == "tls_redirect":
        return ("Plain HTTP was served without redirecting to HTTPS."
                if not obs.get("redirects_to_https") else "HTTP was redirected to HTTPS.")
    if check == "clickjacking":
        return ("The page can be framed (no X-Frame-Options and no CSP frame-ancestors)."
                if obs.get("frameable") else "The page is protected against framing.")
    if check == "directory_listing":
        return (f"The reply looked like a directory index (matched '{obs.get('signature')}')."
                if obs.get("listing_detected") else "The reply was not a directory listing.")
    if check == "server_version":
        disclosures = obs.get("disclosures") or {}
        return ("The server disclosed: " + "; ".join(f"{k}: {v}" for k, v in disclosures.items())
                if disclosures else "No server/version banner was disclosed.")
    return "See the observations for details."


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


def build_proof(result: Any, lang: str = "en") -> Dict[str, Any]:
    """Render a verification result into a human-readable proof."""

    check = result.finding.check
    info = explain_check(check, lang)
    observations: List[Dict[str, Any]] = list(getattr(result, "observations", []) or [])
    obs0 = observations[0] if observations else {}
    decisive = _decisive(check, obs0) if observations else result.reason

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
    if proven:
        headline = f"Proven: {decisive}"
    elif result.verdict is Verdict.NOT_CONFIRMED:
        headline = f"Not confirmed: {decisive}"
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
