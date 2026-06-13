#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import time
import os
from pathlib import Path
import signal
import sys
from copy import deepcopy

INPUT_FILE = "/var/ossec/logs/log_normalized.json"
OUTPUT_FILE = "/var/ossec/logs/log_dedup.json"
OFFSET_FILE = "/var/ossec/logs/.dedup_offset"

WINDOW_SECONDS = 60
POLL_INTERVAL = 1
MAX_CACHE_SIZE = 50000
OFFSET_SAVE_INTERVAL = 2


class DedupService:
    def __init__(self):
        self.cache = {}
        self.running = True
        self.offset = 0

        self.total_processed = 0
        self.total_flushed = 0
        self.total_evicted = 0
        self.start_time = time.time()
        self.last_offset_save = time.time()

    # -------------------------------------------------------------------------
    # Offset handling
    # -------------------------------------------------------------------------
    def load_offset(self):
        if os.path.exists(OFFSET_FILE):
            try:
                with open(OFFSET_FILE, "r", encoding="utf-8") as f:
                    self.offset = int(f.read().strip() or 0)
            except Exception:
                self.offset = 0
        else:
            self.offset = 0

    def save_offset(self, position):
        with open(OFFSET_FILE, "w", encoding="utf-8") as f:
            f.write(str(position))

    # -------------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------------
    def extract_event_time(self, log):
        raw = log.get("time")
        if raw in (None, ""):
            return None
        try:
            return float(raw) / 1000.0
        except Exception:
            return None

    # -------------------------------------------------------------------------
    # Build grouping key
    # -------------------------------------------------------------------------
    def build_key(self, log):
        log_type = log.get("log_type")
        net = log.get("network", {})
        action = log.get("action")
        asset_host = log.get("asset_host")

        if log_type == "waf":
            waf = log.get("waf", {})
            uri = waf.get("uri")
            rule_id = waf.get("terminating_rule_id")
            host_header = waf.get("host_header")

            return (
                f"waf|{net.get('source_ip')}|{net.get('destination_ip')}|"
                f"{host_header}|{uri}|{net.get('method')}|{rule_id}|{action}"
            )

        elif log_type == "vpc":
            return (
                f"vpc|{asset_host}|{net.get('source_ip')}|"
                f"{net.get('destination_ip')}|{net.get('destination_port')}|"
                f"{net.get('protocol')}|{action}"
            )

        elif log_type == "linux":
            linux_evt = log.get("linuxEvent", {})
            program = linux_evt.get("program", "")
            user = linux_evt.get("user", "")
            rule_id = linux_evt.get("ruleID", "")

            return (
                f"linux|{net.get('source_ip')}|{asset_host}|"
                f"{action}|{program}|{user}|{rule_id}"
            )

        elif log_type == "win":
            win_evt = log.get("winEvent", {})
            event_id = win_evt.get("eventID", "")
            target_user = win_evt.get("targetUserName", "")

            return (
                f"win|{asset_host}|{net.get('source_ip')}|"
                f"{event_id}|{target_user}|{action}"
            )

        return None

    # -------------------------------------------------------------------------
    # Flush expired windows
    # -------------------------------------------------------------------------
    def flush_expired(self):
        now = time.time()
        expired = []

        for key, entry in self.cache.items():
            if now - entry["last_update_wallclock"] >= WINDOW_SECONDS:
                self.write_output(key, entry)
                expired.append(key)

        for key in expired:
            del self.cache[key]

    # -------------------------------------------------------------------------
    # Write aggregated event
    # -------------------------------------------------------------------------
    def write_output(self, key, entry):
        duration = max(entry["last_seen"] - entry["first_seen"], 1)
        rate = round(entry["count"] / duration, 2)

        output_event = {
            "log_type": entry["log"].get("log_type"),
            "group_key": key,
            "aggregation": {
                "count": entry["count"],
                "window_seconds": WINDOW_SECONDS,
                "first_seen": entry["first_seen"],
                "last_seen": entry["last_seen"],
                "duration_seconds": round(duration, 2),
                "rate_per_sec": rate
            },
            "sample_event": deepcopy(entry["log"])
        }

        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(output_event, ensure_ascii=False) + "\n")
            f.flush()

        self.total_flushed += 1

    # -------------------------------------------------------------------------
    # Evict oldest cache entry
    # -------------------------------------------------------------------------
    def evict_oldest(self):
        oldest_key = None
        oldest_time = float("inf")

        for key, entry in self.cache.items():
            if entry["last_seen"] < oldest_time:
                oldest_time = entry["last_seen"]
                oldest_key = key

        if oldest_key is not None:
            self.write_output(oldest_key, self.cache[oldest_key])
            del self.cache[oldest_key]
            self.total_evicted += 1

    # -------------------------------------------------------------------------
    # Process incoming line
    # -------------------------------------------------------------------------
    def process_line(self, line):
        try:
            log = json.loads(line)
        except Exception:
            return

        self.total_processed += 1

        key = self.build_key(log)
        if not key:
            return

        event_time = self.extract_event_time(log)
        if event_time is None:
            return

        now = time.time()

        if key in self.cache:
            entry = self.cache[key]
            entry["count"] += 1
            entry["last_seen"] = event_time
            entry["last_update_wallclock"] = now
        else:
            self.cache[key] = {
                "count": 1,
                "first_seen": event_time,
                "last_seen": event_time,
                "last_update_wallclock": now,
                "log": log
            }

        if len(self.cache) > MAX_CACHE_SIZE:
            self.evict_oldest()

    # -------------------------------------------------------------------------
    # Metrics
    # -------------------------------------------------------------------------
    def print_metrics(self):
        uptime = int(time.time() - self.start_time)

        print(
            f"[Metrics] "
            f"uptime={uptime}s "
            f"processed={self.total_processed} "
            f"flushed={self.total_flushed} "
            f"evicted={self.total_evicted} "
            f"cache_size={len(self.cache)}"
        )

    # -------------------------------------------------------------------------
    # Main loop
    # -------------------------------------------------------------------------
    def run(self):
        print("Dedup service started...")

        Path(OUTPUT_FILE).touch(exist_ok=True)
        Path(OFFSET_FILE).touch(exist_ok=True)

        self.load_offset()

        f = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
        st = os.stat(INPUT_FILE)
        current_inode = st.st_ino

        file_size = os.path.getsize(INPUT_FILE)
        if self.offset > file_size:
            self.offset = 0

        f.seek(self.offset)

        last_metrics_print = time.time()

        try:
            while self.running:
                try:
                    st = os.stat(INPUT_FILE)
                    new_inode = st.st_ino
                    new_size = st.st_size
                except FileNotFoundError:
                    time.sleep(POLL_INTERVAL)
                    continue

                if new_inode != current_inode:
                    print("Log rotation detected. Reopening file...")
                    f.close()
                    f = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
                    current_inode = new_inode
                    self.offset = 0
                    f.seek(0)

                elif new_size < f.tell():
                    print("Input file truncated. Resetting offset...")
                    f.close()
                    f = open(INPUT_FILE, "r", encoding="utf-8", errors="replace")
                    self.offset = 0
                    f.seek(0)

                line = f.readline()

                if not line:
                    self.flush_expired()
                    time.sleep(POLL_INTERVAL)
                    continue

                self.process_line(line)
                self.offset = f.tell()

                now = time.time()

                if now - self.last_offset_save >= OFFSET_SAVE_INTERVAL:
                    self.save_offset(self.offset)
                    self.last_offset_save = now

                if now - last_metrics_print >= 30:
                    self.print_metrics()
                    last_metrics_print = now

        finally:
            self.save_offset(self.offset)
            f.close()

    # -------------------------------------------------------------------------
    # Graceful shutdown
    # -------------------------------------------------------------------------
    def shutdown(self, signum, frame):
        print("Flushing remaining logs before shutdown...")

        for key, entry in list(self.cache.items()):
            self.write_output(key, entry)

        self.cache.clear()
        self.running = False
        sys.exit(0)


if __name__ == "__main__":
    service = DedupService()

    signal.signal(signal.SIGINT, service.shutdown)
    signal.signal(signal.SIGTERM, service.shutdown)

    service.run()
