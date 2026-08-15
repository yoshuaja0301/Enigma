"""Reporting layer: JSON, Markdown and summary metrics."""

from .html import render_dashboard_html, render_report_html, to_html
from .json import build_report, to_json
from .markdown import to_markdown
from .summary import Summary, summarize

__all__ = [
    "to_json",
    "build_report",
    "to_markdown",
    "to_html",
    "render_report_html",
    "render_dashboard_html",
    "summarize",
    "Summary",
]
