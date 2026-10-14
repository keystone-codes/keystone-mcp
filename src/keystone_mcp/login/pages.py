"""Built-in HTML for sign-in, consent and error pages (card X13)."""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import quote

# Language switcher order is fixed (Latin codes) so readers can find their language.
LANG_SWITCHER_ORDER: tuple[str, ...] = ("en", "ru", "he", "ar")

_PAGE_STYLES = """
  :root {
    --bg: #f4f5f7;
    --card: #ffffff;
    --text: #1b1f24;
    --muted: #5b6470;
    --line: #d9dee5;
    --accent: #1f5fbf;
    --accent-text: #ffffff;
    --accent-soft: #e8f0fc;
    --warn-bg: #fff7e6;
    --warn-line: #e6a700;
    --warn-text: #7a4e00;
    --error-bg: #fdecec;
    --error-line: #d93025;
    --error-text: #8a1c14;
    --radius: 12px;
    --shadow: 0 1px 2px rgba(16, 24, 40, .06), 0 8px 24px rgba(16, 24, 40, .08);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0f1216;
      --card: #171b21;
      --text: #e8ecf1;
      --muted: #9aa5b3;
      --line: #2a313a;
      --accent: #6ea0ff;
      --accent-text: #0f1216;
      --accent-soft: #1b2a44;
      --warn-bg: #2a2110;
      --warn-line: #d9a400;
      --warn-text: #ffd57a;
      --error-bg: #2d1614;
      --error-line: #ff6b61;
      --error-text: #ffb3ad;
      --shadow: 0 1px 2px rgba(0,0,0,.5), 0 8px 24px rgba(0,0,0,.45);
    }
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", sans-serif;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 24px 16px 40px;
  }
  main.card {
    width: 100%;
    max-width: 440px;
    background: var(--card);
    border: 1px solid var(--line);
    border-radius: var(--radius);
    box-shadow: var(--shadow);
    padding: 28px 24px 24px;
    margin-top: 32px;
  }
  .brand {
    display: flex; align-items: center; gap: 10px;
    margin-bottom: 4px;
  }
  .brand svg { width: 28px; height: 28px; flex: none; }
  .brand h1 { font-size: 1.25rem; margin: 0; letter-spacing: .01em; }
  .subtitle { color: var(--muted); margin: 0 0 20px; font-size: .95rem; }

  .consent {
    border: 1px solid var(--line);
    border-radius: 10px;
    padding: 16px;
    margin: 0 0 20px;
    background: color-mix(in srgb, var(--card) 92%, var(--accent-soft));
  }
  .consent h2 { font-size: 1rem; margin: 0 0 12px; }
  .row { display: grid; grid-template-columns: 1fr; gap: 2px; margin: 0 0 10px; }
  .row .k { color: var(--muted); font-size: .85rem; }
  .row .v { font-weight: 600; word-break: break-word; }
  .chip {
    display: inline-block; padding: 2px 8px; border-radius: 999px;
    background: var(--accent-soft); color: var(--text); font-weight: 600; font-size: .95rem;
  }
  .host { font-size: 1.15rem; }
  .url {
    font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    color: var(--muted); word-break: break-all; margin: 0 0 12px;
  }
  .callout {
    display: flex; gap: 10px; align-items: flex-start;
    border-inline-start: 4px solid var(--warn-line);
    background: var(--warn-bg); color: var(--warn-text);
    border-radius: 8px; padding: 10px 12px; font-size: .92rem; margin: 0;
  }
  .callout svg { width: 20px; height: 20px; flex: none; margin-top: 2px; }
  .alert {
    display: flex; gap: 10px; align-items: flex-start;
    border-inline-start: 4px solid var(--error-line);
    background: var(--error-bg); color: var(--error-text);
    border-radius: 8px; padding: 10px 12px; font-size: .92rem; margin: 0 0 16px;
  }
  .alert svg { width: 20px; height: 20px; flex: none; margin-top: 2px; }

  .btn {
    display: flex; align-items: center; justify-content: center; gap: 10px;
    width: 100%; padding: 12px 14px; border-radius: 10px;
    border: 1px solid var(--line); background: var(--card); color: var(--text);
    font: inherit; font-weight: 600; cursor: pointer; text-decoration: none;
  }
  .btn:hover { border-color: var(--accent); }
  .btn:focus-visible { outline: 3px solid var(--accent-soft); outline-offset: 1px; border-color: var(--accent); }
  .btn.primary { background: var(--accent); color: var(--accent-text); border-color: var(--accent); }
  .btn.primary:hover { filter: brightness(1.05); }
  .btn svg { width: 18px; height: 18px; }
  .providers { display: grid; gap: 10px; margin: 0 0 18px; }
  .or {
    display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: .85rem; margin: 0 0 16px;
  }
  .or::before, .or::after { content: ""; flex: 1; height: 1px; background: var(--line); }

  form.fields { display: grid; gap: 14px; }
  label { display: grid; gap: 6px; font-size: .9rem; font-weight: 600; }
  input {
    font: inherit; padding: 11px 12px; border-radius: 10px;
    border: 1px solid var(--line); background: var(--card); color: var(--text); width: 100%;
  }
  input:focus-visible { outline: 3px solid var(--accent-soft); outline-offset: 0; border-color: var(--accent); }
  .help { color: var(--muted); font-size: .82rem; font-weight: 400; }

  footer {
    width: 100%; max-width: 440px; display: flex; justify-content: space-between; align-items: center;
    color: var(--muted); font-size: .8rem; margin-top: 14px; padding: 0 4px;
  }
  footer nav a { color: var(--muted); text-decoration: none; margin-inline-start: 10px; }
  footer nav a[aria-current="true"] { color: var(--text); font-weight: 600; text-decoration: underline; }
"""

_SHIELD_SVG = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
      <path d="M12 2.5 4 6v6c0 4.6 3.4 8.3 8 9.5 4.6-1.2 8-4.9 8-9.5V6l-8-3.5Z"/>
      <path d="M9.5 12.5h5M12 10v5"/>
    </svg>"""

_WARN_SVG = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
        <path d="M12 3 2.5 20h19L12 3Z"/><path d="M12 9v5M12 17.5v.5"/>
      </svg>"""

_ALERT_SVG = """<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
      <circle cx="12" cy="12" r="9"/><path d="M12 8v5M12 16v.5"/>
    </svg>"""

_GOOGLE_SVG = """<svg viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M21.6 12.2c0-.7-.1-1.3-.2-1.9H12v3.7h5.4c-.2 1.2-.9 2.3-2 3v2.5h3.2c1.9-1.7 3-4.3 3-7.3Z"/><path fill="currentColor" d="M12 22c2.7 0 5-.9 6.6-2.4l-3.2-2.5c-.9.6-2 1-3.4 1-2.6 0-4.8-1.8-5.6-4.1H3.1v2.6A10 10 0 0 0 12 22Z"/><path fill="currentColor" d="M6.4 14a6 6 0 0 1 0-3.9V7.5H3.1a10 10 0 0 0 0 9l3.3-2.5Z"/><path fill="currentColor" d="M12 6c1.5 0 2.8.5 3.8 1.5l2.8-2.8A10 10 0 0 0 3.1 7.5L6.4 10C7.2 7.8 9.4 6 12 6Z"/></svg>"""


@dataclass(frozen=True, slots=True)
class FieldView:
    name: str
    input_type: str
    label: str
    help_key: str | None
    autocomplete: str
    inputmode: str | None


@dataclass(frozen=True, slots=True)
class ProviderView:
    name: str
    kind: str
    title: str
    fields: tuple[FieldView, ...]


def build_lang_links(
    lang: str,
    *,
    txn_query: str,
    login_path: str = "/login",
) -> tuple[tuple[str, str, bool], ...]:
    """Build footer language links preserving ``txn`` when present."""
    links: list[tuple[str, str, bool]] = []
    for code in LANG_SWITCHER_ORDER:
        code_upper = code.upper()
        if txn_query:
            href = f"{login_path}?{txn_query}lang={quote(code)}"
        else:
            href = f"{login_path}?lang={quote(code)}"
        links.append((code_upper, href, code == lang))
    return tuple(links)


def page_shell(
    *,
    lang: str,
    direction: str,
    title: str,
    body: str,
    brand: str,
    lang_links: Sequence[tuple[str, str, bool]],
    lang_nav_label: str,
) -> str:
    brand_esc = html.escape(brand)
    nav_parts: list[str] = []
    for code, href, is_current in lang_links:
        if is_current:
            nav_parts.append(f'<span aria-current="true">{html.escape(code)}</span>')
        else:
            nav_parts.append(f'<a href="{html.escape(href)}">{html.escape(code)}</a>')
    nav_html = "".join(nav_parts)
    return f"""<!doctype html>
<html lang="{html.escape(lang)}" dir="{html.escape(direction)}"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
{_PAGE_STYLES}
</style>
</head>
<body>
<main class="card">
{body}
</main>
<footer>
  <span>{brand_esc}</span>
  <nav aria-label="{html.escape(lang_nav_label)}">{nav_html}</nav>
</footer>
</body></html>"""


def _page_title(brand: str, t_title: str) -> str:
    if " — " in t_title:
        return f"{brand} — {t_title.split(' — ', 1)[1]}"
    return f"{brand} — {t_title}"


def _consent_section(
    t: Mapping[str, str],
    client_name: str | None,
    redirect_uri: str,
    redirect_location: str,
) -> str:
    name = (client_name or "").strip()
    display_name = html.escape(name) if name else html.escape(t["consent_unnamed"])
    location = html.escape(redirect_location)
    full_redirect = html.escape(redirect_uri)
    return f"""
  <section class="consent" aria-labelledby="consent-title">
    <h2 id="consent-title">{html.escape(t["consent_title"])}</h2>
    <div class="row">
      <span class="k">{html.escape(t["consent_app"])}</span>
      <span class="v"><span class="chip">{display_name}</span></span>
    </div>
    <div class="row">
      <span class="k">{html.escape(t["consent_redirect"])}</span>
      <span class="v host">{location}</span>
    </div>
    <p class="url">{full_redirect}</p>
    <p class="callout">
      {_WARN_SVG}
      <span>{html.escape(t["consent_warning"])}</span>
    </p>
  </section>"""


def _redirect_provider_html(
    provider: ProviderView,
    t: Mapping[str, str],
    txn: str,
    csrf: str,
) -> str:
    button_text = html.escape(t["login_with"].format(provider=provider.title))
    icon = _GOOGLE_SVG if provider.name == "google" else ""
    return f"""
    <form method="post" action="/login/{html.escape(provider.name)}">
      <input type="hidden" name="txn" value="{txn}">
      <input type="hidden" name="csrf" value="{csrf}">
      <button class="btn" type="submit">{icon}{button_text}</button>
    </form>"""


def _form_provider_html(provider: ProviderView, t: Mapping[str, str], txn: str) -> str:
    fields: list[str] = []
    for field in provider.fields:
        input_attrs = [
            f'id="{html.escape(field.name)}"',
            f'name="{html.escape(field.name)}"',
            f'type="{html.escape(field.input_type)}"',
            f'autocomplete="{html.escape(field.autocomplete)}"',
            "required",
        ]
        if field.inputmode:
            input_attrs.append(f'inputmode="{html.escape(field.inputmode)}"')
        help_html = ""
        if field.help_key:
            help_html = f'<span class="help">{html.escape(t[field.help_key])}</span>'
        fields.append(
            f"""    <label for="{html.escape(field.name)}">{html.escape(field.label)}
      <input {" ".join(input_attrs)}>
      {help_html}
    </label>"""
        )
    fields_block = "\n".join(fields)
    return f"""
  <form class="fields" method="post" action="/login">
    <input type="hidden" name="txn" value="{txn}">
{fields_block}
    <button class="btn primary" type="submit">{html.escape(t["submit"])}</button>
  </form>"""


def render_consent_page(
    *,
    lang: str,
    t: Mapping[str, str],
    brand: str,
    client_name: str | None,
    redirect_uri: str,
    redirect_location: str,
    providers: Sequence[ProviderView],
    txn: str,
    csrf: str | None,
    error_key: str | None,
    txn_query: str,
) -> str:
    direction = "rtl" if lang in {"he", "ar"} else "ltr"
    brand_esc = html.escape(brand)
    txn_esc = html.escape(txn)
    csrf_esc = html.escape(csrf or "")

    header = f"""
  <div class="brand">
    {_SHIELD_SVG}
    <h1>{brand_esc}</h1>
  </div>
  <p class="subtitle">{html.escape(t["subtitle"])}</p>"""

    consent = _consent_section(t, client_name, redirect_uri, redirect_location)

    error_block = ""
    login_error_hidden = ""
    if error_key:
        error_block = f"""
  <div class="alert" role="alert">
    {_ALERT_SVG}
    <span>{html.escape(t[error_key])}</span>
  </div>"""
        login_error_hidden = (
            f'<input type="hidden" name="login_error" value="{html.escape(error_key)}">'
        )

    redirect_providers = [p for p in providers if p.kind == "redirect"]
    form_providers = [p for p in providers if p.kind == "form"]

    provider_forms = "".join(
        _redirect_provider_html(p, t, txn_esc, csrf_esc) for p in redirect_providers
    )
    providers_block = ""
    if provider_forms:
        providers_block = f"""
  <div class="providers">
{provider_forms}
  </div>"""

    or_block = ""
    form_block = ""
    if redirect_providers and form_providers:
        or_block = f'<p class="or">{html.escape(t["or_api_key"])}</p>'
    if form_providers:
        form_block = _form_provider_html(form_providers[0], t, txn_esc)

    lang_links = build_lang_links(lang, txn_query=txn_query)
    body = f"""{header}
{consent}
{error_block}
{login_error_hidden}
{providers_block}
{or_block}
{form_block}"""

    return page_shell(
        lang=lang,
        direction=direction,
        title=_page_title(brand, t["title"]),
        body=body,
        brand=brand,
        lang_links=lang_links,
        lang_nav_label=t["lang_switcher_label"],
    )


def render_error_page(
    *,
    lang: str,
    t: Mapping[str, str],
    brand: str,
    error_key: str,
    status_code: int,
    txn_query: str = "",
) -> str:
    direction = "rtl" if lang in {"he", "ar"} else "ltr"
    brand_esc = html.escape(brand)
    message = html.escape(t[error_key])
    hint_key = f"error_hint_{error_key.removeprefix('error_')}"
    hint = t.get(hint_key, t["error_hint_generic"])
    lang_links = build_lang_links(lang, txn_query=txn_query)

    body = f"""
  <div class="brand">
    {_SHIELD_SVG}
    <h1>{brand_esc}</h1>
  </div>
  <div class="alert" role="alert" style="margin-top:12px">
    {_ALERT_SVG}
    <span><strong>{message}</strong></span>
  </div>
  <p style="margin:0 0 6px">{html.escape(hint)}</p>
  <p class="help" style="margin:0">{html.escape(t["error_code_hint"])} <code>{html.escape(error_key)}</code></p>"""

    return page_shell(
        lang=lang,
        direction=direction,
        title=_page_title(brand, t["title"]),
        body=body,
        brand=brand,
        lang_links=lang_links,
        lang_nav_label=t["lang_switcher_label"],
    )
