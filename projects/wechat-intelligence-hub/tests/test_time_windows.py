from datetime import datetime, timezone, timedelta
import os
import sqlite3
import time
import unittest
from unittest.mock import patch

import intelligence_views as views
import wechat_intelligence_hub as hub
from message_time import timestamp_epoch


class TimeWindowTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {'TZ': 'Asia/Shanghai'})
        self.env.start()
        if hasattr(time, 'tzset'):
            time.tzset()
        self.conn = sqlite3.connect(':memory:')
        self.conn.row_factory = sqlite3.Row
        hub.init_radar_db(self.conn)

    def tearDown(self):
        self.conn.close()
        self.env.stop()
        if hasattr(time, 'tzset'):
            time.tzset()

    def insert(self, stamp, text, sender='Contact'):
        self.conn.execute('insert into messages(hash,chat,sender,time,content,source_file,created_at) values(?,?,?,?,?,?,?)',
                          (stamp+text, 'Contact', sender, stamp, text, 'private', stamp))

    def test_mixed_old_and_iso_rows_use_instants_not_text_order(self):
        self.insert('2026-09-11T09:00:00+08:00', 'outside')
        self.insert('2026-09-11 18:00:00', 'local')
        self.insert('2026-09-12T01:00:00Z', 'utc')
        self.insert('2026-09-12T10:00:00+08:00', 'offset')
        rows = views._window_messages(self.conn, '2026-09-11 16:00:00', '2026-09-12 16:00:00')
        self.assertEqual([r['content'] for r in rows], ['local', 'utc', 'offset'])
        self.assertEqual(len(views._window_messages(self.conn, '2026-09-11 16:00:00', '2026-09-12 16:00:00')), 3)

    def test_contact_daily_includes_latest_iso_and_does_not_rewrite_old_rows(self):
        self.insert('2026-09-11T09:00:00+08:00', 'old')
        self.insert('2026-09-12 11:00:00', 'my answer', 'Owner')
        self.insert('2026-09-12T10:00:00+08:00', '合作报价多少？')
        before = [tuple(r) for r in self.conn.execute('select * from messages')]
        rows = hub.build_contact_daily_rows(self.conn, '2026-09-11 16:00:00', '2026-09-12 16:00:00',
                                           {'contact': {'商单推广'}}, ['Owner'])
        self.assertEqual(rows[0]['消息数'], 2)
        self.assertEqual(rows[0]['最后发言人'], 'Owner')
        self.assertEqual(rows[0]['状态'], '等待对方')
        self.assertEqual(before, [tuple(r) for r in self.conn.execute('select * from messages')])

    def test_brief_timezone_aware_now_does_not_crash(self):
        self.insert('2026-09-12T10:00:00+08:00', '合作报价多少？')
        _, meta = views.brief_report(self.conn, now=datetime(2026,9,12,16,tzinfo=timezone(timedelta(hours=8))))
        self.assertEqual(meta['messages'], 1)

    def test_boundaries_and_invalid_window(self):
        self.insert('2026-09-12T16:00:00+08:00', 'end')
        self.assertEqual(views._window_messages(self.conn, '2026-09-11 16:00:00', '2026-09-12 16:00:00'), [])
        with self.assertRaises(ValueError):
            views._window_messages(self.conn, 'invalid', '2026-09-12')
        self.assertIsNone(timestamp_epoch('not-a-date'))

    def test_self_name_requires_exact_nonempty_alias(self):
        self.assertFalse(views.is_self_sender('Owner Agency', ['Owner']))
        self.assertFalse(views.is_self_sender('Someone', ['']))
        self.assertTrue(views.is_self_sender(' owner ', ['Owner']))

    def test_normalization_does_not_change_iso_storage_identity(self):
        value = '2026-09-12T10:00:00+08:00'
        self.assertEqual(hub.normalize_time(value), value)
        self.assertEqual(hub.parse_time_for_filter(value), datetime(2026, 9, 12, 10))

    def test_compound_acknowledgements_do_not_create_reply_tasks(self):
        for content in ['好的，收到', '好滴，辛苦老师了', '谢谢老师！']:
            self.assertIsNotNone(hub.CONTACT_ACK_TERMS.fullmatch(content))
        for content in ['好的，报价多少？', '收到，明天发我初稿', '可以吗', '好的，收到？']:
            self.assertIsNone(hub.CONTACT_ACK_TERMS.fullmatch(content))


if __name__ == '__main__':
    unittest.main()
