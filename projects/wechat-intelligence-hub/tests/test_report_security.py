from html.parser import HTMLParser
from argparse import Namespace
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import report_bundle_flagship as flagship
import report_bundle_html as legacy
import wechat_intelligence_hub as hub
from report_security import protect_document, safe_href, sanitize_fragment


class Tags(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class ReportSecurityTests(unittest.TestCase):
    def assert_inert(self, fragment):
        for tag, attrs in Tags(fragment).tags:
            self.assertNotIn(tag, {'script', 'img', 'iframe', 'svg', 'math', 'object', 'form', 'input', 'style'})
            self.assertFalse(any(k.startswith('on') or k in {'style', 'src', 'srcdoc'} for k in attrs))
            if 'href' in attrs:
                self.assertIsNotNone(safe_href(attrs['href']))

    def test_allowlist_blocks_active_markup_and_tracking(self):
        payload = '<p onclick="alert(1)">hello</p><img src="https://invalid.example/pixel" onerror="alert(1)">'
        payload += '<svg><a xlink:href="javascript:alert(1)">x</a></svg><iframe srcdoc="x"></iframe>'
        payload += '<style>body{display:none}</style><script>window.bad=1</script>'
        payload += '<a href="jAvAsCrIpT:alert(1)">bad</a><a href="https://example.com">ok</a>'
        cleaned = sanitize_fragment(payload)
        self.assert_inert(cleaned)
        self.assertIn('hello', cleaned)
        self.assertIn('https://example.com', cleaned)
        self.assertNotIn('window.bad', cleaned)

    def test_dangerous_schemes_and_protocol_relative_links_are_removed(self):
        for url in ['javascript:alert(1)', 'java\tscript:alert(1)', 'data:text/html,test',
                    'file:///etc/passwd', '//invalid.example', '\\invalid.example',
                    '%2f%2finvalid.example', 'https://user:pass@example.com']:
            with self.subTest(url=url):
                self.assertIsNone(safe_href(url))
        for url in ['https://example.com/?x=1&y=2', '#/groups', '#section', 'group-daily/report.md']:
            self.assertEqual(safe_href(url), url)

    def test_tables_headings_and_code_survive(self):
        cleaned = sanitize_fragment('<h2 id="source-topic">Topic</h2><table><tr><td>Evidence</td></tr></table>'
                                    '<pre><code>&lt;script&gt;example&lt;/script&gt;</code></pre>', id_prefix='source-')
        self.assertIn('id="source-topic"', cleaned)
        self.assertIn('<table>', cleaned)
        self.assertIn('&lt;script&gt;', cleaned)
        self.assertNotIn('id=', sanitize_fragment('<p id="search-input">bad id</p>', id_prefix='source-'))

    def test_missing_sanitizer_fails_before_publishing_any_html(self):
        for renderer in (flagship, legacy):
            with tempfile.TemporaryDirectory() as tmp, patch.dict('sys.modules', {'nh3': None}):
                root = Path(tmp)
                (root / 'final_report.md').write_text('# Report\n\nhello', encoding='utf-8')
                with self.assertRaisesRegex(RuntimeError, 'nh3'):
                    render = legacy._render_legacy_report_bundle if renderer is legacy else renderer.render_report_bundle
                    render(root)
                self.assertFalse((root / 'wechat_daily_report.html').exists())

    @unittest.skipUnless(shutil.which('pandoc'), 'Pandoc integration requires pandoc')
    def test_both_real_pandoc_renderers_block_stored_xss(self):
        for renderer in (flagship, legacy):
            with self.subTest(renderer=renderer.__name__), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / 'final_report.md').write_text(
                    '# Report\n\n## Topic\n\n<img src=x onerror="window.bad=1">\n\n'
                    '[bad](javascript:alert(1))\n\n[ok](https://example.com)\n\n'
                    '| Key | Value |\n| --- | --- |\n| A | B |\n', encoding='utf-8')
                source = renderer.discover_report_sources(root)[0]
                self.assert_inert(renderer._pandoc_fragment(source, shutil.which('pandoc')))
                render = legacy._render_legacy_report_bundle if renderer is legacy else renderer.render_report_bundle
                html = render(root)[0].read_text()
                tags = Tags(html).tags
                self.assertEqual(sum(tag == 'script' for tag, _ in tags), 1)
                self.assertIn('Content-Security-Policy', html)
                self.assertIn("connect-src &#x27;none&#x27;", html)
                self.assertIn('<table>', html)

    def test_document_rejects_unexpected_script(self):
        with self.assertRaises(RuntimeError):
            protect_document('<meta charset="utf-8"><script>app()</script><script>bad()</script>')
        with self.assertRaises(RuntimeError):
            protect_document('<script>app()</script>')

    @unittest.skipUnless(shutil.which('pandoc'), 'Pandoc integration requires pandoc')
    def test_single_markdown_report_uses_static_csp_without_embedded_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / 'report.md'
            source.write_text('# Report\n\n<img src=x onerror="window.bad=1">\n\n'
                              '![tracking](https://invalid.example/pixel)\n\n[bad](javascript:alert(1))')
            hub.render_report_command(Namespace(source=str(source), out=None, css=None, title=None))
            html = source.with_suffix('.html').read_text()
            tags = Tags(html).tags
            self.assertFalse(any(tag in {'script', 'img', 'iframe'} for tag, _ in tags))
            self.assertIn("script-src &#x27;none&#x27;", html)

    def test_known_parent_links_become_routes_unknown_files_are_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'group-daily').mkdir()
            (root / 'final_report.md').write_text('# Report\n\n## Action\n\nhello')
            (root / 'group-daily' / 'group_daily_brief.md').write_text(
                '# Groups\n\n[Overview](../final_report.md)\n\n[Unknown](../../private.txt)')
            for renderer in (flagship, legacy):
                sources = renderer.discover_report_sources(root)
                source = next(s for s in sources if s.path.name == 'group_daily_brief.md')
                fragment = sanitize_fragment('<a href="../final_report.md">Overview</a>'
                    '<a href="../../private.txt">Unknown</a>', allow_parent=True)
                if renderer is flagship:
                    pages = flagship.build_report_pages(sources)
                    mapping = {s.path.resolve(): p for p in pages for s in p.sources}
                    html = flagship._rewrite_html_links(fragment, source=source, source_pages=mapping)
                else:
                    mapping = {s.path.resolve(): s.source_id for s in sources}
                    html = legacy._rewrite_links(fragment, source=source, source_ids=mapping)
                links = [attrs for tag, attrs in Tags(html).tags if tag == 'a']
                self.assertTrue(links[0]['href'].startswith('#'))
                self.assertNotIn('href', links[1])

    def test_old_third_level_group_headings_still_fold(self):
        html = flagship._wrap_key_group_sections('<h3 id="sample-group">Sample</h3><p>Evidence</p>')
        self.assertIn('class="key-group-card"', html)
        self.assertIn('id="sample-group"', html)
        self.assertIn('Evidence', html)


if __name__ == '__main__':
    unittest.main()
