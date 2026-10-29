"""Synthetic regression cases only; no personal chats or credentials."""
from datetime import datetime
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
import shutil
from unittest.mock import patch

import intelligence_views
try:
    import wechat_intelligence_hub as radar
except ModuleNotFoundError:
    import wechat_deal_radar as radar


class FollowupRegressionTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        radar.init_radar_db(self.conn)
        self.conn.execute("insert into runs(id,run_type,since_time,until_time,output_dir,created_at) values (1,'test','','','','2026-10-17')")
        self.profile = patch.object(radar, "ACTIVE_PROFILE", {"contact_daily": {"scope": "hybrid"}})
        self.profile.start()

    def tearDown(self):
        self.profile.stop()
        self.conn.close()

    def m(self, content, sender="我", hour=9, identity="customer-a", chat="测试客户"):
        return radar.Message(chat, sender, f"2026-10-16 {hour:02d}:00:00", content, f"wechat-cli:timeline:{identity}")

    def insert(self, *rows):
        return radar.insert_messages_to_db(self.conn, 1, list(rows), "2026-10-17")

    def contacts(self):
        return radar.build_contact_daily_rows(self.conn, "2026-10-16", "2026-10-17", {}, ["我"])

    def promises(self):
        return radar.find_open_contact_promises(self.conn, "测试客户", "2026-10-17", ["我"])

    def test_first_inbound_untagged_request_is_visible(self):
        self.insert(self.m("我们需要企业AI培训，请问报价和近期档期？", sender="客户"))
        rows = self.contacts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["状态"], "待回复")
        self.assertEqual(rows[0]["商机列表"], [])

    def test_priority_labels_only_remains_opt_in_filter(self):
        self.insert(self.m("请问企业培训怎么报价？", sender="客户"))
        with patch.object(radar, "ACTIVE_PROFILE", {"contact_daily": {"scope": "priority_labels_only"}}):
            self.assertEqual(self.contacts(), [])

    def test_social_chatter_is_not_new_commercial_contact(self):
        self.insert(self.m("今天去公园散步，天气不错", sender="客户"))
        self.assertEqual(self.contacts(), [])

    def test_generic_brand_news_is_not_inbound_request(self):
        self.insert(self.m("品牌推广案例合集", sender="客户"))
        self.assertEqual(self.contacts(), [])

    def test_other_round_completion_does_not_clear(self):
        self.insert(self.m("我明天整理甲项目9月初稿发你"), self.m("甲项目8月初稿已经提交了", hour=10))
        self.assertEqual(len(self.promises()), 1)

    def test_cancelled_old_round_is_not_open(self):
        self.insert(self.m("我明天整理初稿发你"), self.m("这一轮取消了，旧稿不用交了，下个月换新brief再联系", sender="客户", hour=10))
        self.assertEqual(self.promises(), [])

    def test_other_project_completion_does_not_clear_promise(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("乙项目的数据已经回传了", hour=10))
        self.assertEqual(len(self.promises()), 1)

    def test_other_project_same_deliverable_does_not_clear(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("乙项目初稿已经提交了", hour=10))
        self.assertEqual(len(self.promises()), 1)

    def test_brand_names_without_spaces_are_not_merged(self):
        for first, second in [("SearchDemo", "VideoDemo"), ("飞书项目", "文心项目")]:
            with self.subTest(first=first):
                rows = [vars(self.m(f"我明天整理{first}初稿发你")), vars(self.m(f"{second}初稿已经提交了", hour=10))]
                self.assertEqual(len(intelligence_views.open_promise_rows(rows, ["我"])), 1)

    def test_same_project_completion_clears(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("甲项目初稿已经提交了", hour=10))
        self.assertEqual(self.promises(), [])

    def test_other_project_cancellation_does_not_clear(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("乙项目取消了，旧稿不用交了", sender="客户", hour=10))
        self.assertEqual(len(self.promises()), 1)

    def test_multiple_project_promises_are_retained(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("我明天整理乙项目方案发你", hour=10))
        self.assertEqual(len(self.promises()), 2)
        self.insert(self.m("甲项目初稿已经提交了", hour=11))
        self.assertEqual(len(self.promises()), 1)
        self.assertIn("乙项目", self.promises()[0]["内容"])

    def test_vague_completion_does_not_clear_multiple(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("我明天整理乙项目初稿发你", hour=10), self.m("已经完成了", hour=11))
        self.assertEqual(len(self.promises()), 2)

    def test_negative_conditional_and_future_are_not_completion(self):
        for text in ["甲项目初稿还没提交", "甲项目初稿明天提交", "如果这一轮取消了就不用交了", "甲项目初稿没有完成", "甲项目初稿是否已经提交了？"]:
            with self.subTest(text=text):
                rows = [vars(self.m("我明天整理甲项目初稿发你")), vars(self.m(text, hour=10))]
                self.assertEqual(len(intelligence_views.open_promise_rows(rows, ["我"])), 1)

    def test_completion_from_other_person_is_not_my_completion(self):
        self.insert(self.m("我明天整理甲项目初稿发你"), self.m("甲项目初稿已经提交了", sender="客户", hour=10))
        self.assertEqual(len(self.promises()), 1)

    def test_brief_uses_same_cancellation_logic(self):
        self.insert(self.m("我明天整理初稿发你"), self.m("这一轮取消了，旧稿不用交了", sender="客户", hour=10))
        _, meta = intelligence_views.brief_report(self.conn, hours=24, now=datetime(2026, 10, 17), self_names=["我"])
        self.assertEqual(meta["open_promises"], 0)

    def test_same_name_different_identity_keeps_both(self):
        a = self.m("请问培训报价？", sender="客户")
        b = self.m("请问培训报价？", sender="客户", identity="customer-b")
        self.assertNotEqual(radar.message_hash(a), radar.message_hash(b))
        self.assertEqual(len(radar.dedupe_messages([a, b, a])), 2)
        self.assertEqual(self.insert(a, b), (2, 0))
        self.assertEqual(self.insert(a, b), (0, 0))
        self.assertEqual(len(self.contacts()), 2)

    def test_other_identity_cannot_clear_promise(self):
        self.insert(self.m("我明天整理初稿发你"), self.m("初稿已经提交了", hour=10, identity="customer-b"))
        self.assertEqual(len(self.promises()), 1)

    def test_search_retains_reader_identity_and_matches_timeline(self):
        original = self.m("请问报价？", sender="客户")
        rows = radar.rows_to_messages([{"chat": "测试客户", "talker": "customer-a", "sender": "客户", "time": original.time, "content": original.content}], "wechat-cli:search:test")
        self.assertEqual(radar.message_hash(rows[0]), radar.message_hash(original))

    def test_legacy_hash_upgrade_preserves_id_fts_and_links(self):
        row = self.m("请问培训报价？ https://example.org/brief", sender="客户")
        self.insert(row)
        old_id = self.conn.execute("select id from messages").fetchone()[0]
        digest = hashlib.sha256("\n".join([row.chat, row.sender, row.time, row.content]).encode()).hexdigest()
        self.conn.execute("update messages set hash = ?", (digest,))
        self.assertEqual(self.insert(row), (0, 0))
        self.assertEqual(self.conn.execute("select id from messages").fetchone()[0], old_id)
        self.assertEqual(self.conn.execute("select rowid from messages_fts").fetchone()[0], old_id)
        self.assertEqual(self.conn.execute("select message_id from message_links").fetchone()[0], old_id)
        self.assertEqual(self.conn.execute("select hash from messages").fetchone()[0], radar.message_hash(row))

    def test_legacy_collision_is_not_migrated_to_other_person(self):
        a = self.m("同一条消息")
        self.insert(a)
        digest = hashlib.sha256("\n".join([a.chat, a.sender, a.time, a.content]).encode()).hexdigest()
        self.conn.execute("update messages set hash = ?", (digest,))
        self.assertEqual(self.insert(self.m("同一条消息", identity="customer-b")), (1, 0))
        self.assertEqual(self.insert(a), (0, 0))
        self.assertEqual(self.conn.execute("select count(*) from messages").fetchone()[0], 2)

    def test_generic_file_import_keeps_legacy_dedupe(self):
        a = radar.Message("客户", "我", "2026-10-16", "内容", "one.json")
        b = radar.Message("客户", "我", "2026-10-16", "内容", "two.json")
        self.assertEqual(self.insert(a, b), (1, 0))

    def test_all_project_actions_are_visible_in_report(self):
        self.insert(self.m("甲项目初稿和乙项目结算分别跟进", sender="客户"))
        for name, stage, action in [("甲项目", "待创作", "提交甲初稿"), ("乙项目", "已发布待结算", "催乙回款")]:
            self.conn.execute("insert into opportunities(opportunity_key,chat,title,stage,status,priority,next_action,created_at,updated_at) values (?,'测试客户',?,?,'active',5,?,'2026-10-16','2026-10-16')", (name, name, stage, action))
        rows = self.contacts()
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0]["商机列表"]), 2)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "contact_daily.md"
            radar.write_contact_daily_report(path, rows, "2026-10-16", "2026-10-17")
            text = path.read_text()
            self.assertIn("提交甲初稿", text)
            self.assertIn("催乙回款", text)
            if shutil.which("pandoc"):
                from report_bundle_flagship import render_report_bundle
                contact_dir = Path(tmp) / "contact-daily"
                contact_dir.mkdir()
                path.rename(contact_dir / "contact_daily_brief.md")
                html, _, _ = render_report_bundle(Path(tmp))
                rendered = html.read_text()
                self.assertIn("提交甲初稿", rendered)
                self.assertIn("催乙回款", rendered)


if __name__ == "__main__":
    unittest.main()
