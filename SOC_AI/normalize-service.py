#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Log Normalizer for AWS WAF, VPC Flow, Windows, and Linux Logs
Supports WAF, VPC Flow, Windows Event, and Linux syslog normalization
"""

import json
import os
import time
from typing import Optional

# Configuration
ARCHIVES_PATH = "/var/ossec/logs/archives/archives.json"
OUTPUT_PATH = "/var/ossec/logs/log_normalized.json"

# Real paths seen in archives.json
WAF_LOCATION_PREFIX = "/tmp/aws-waf/waf/"
VPC_LOCATION_PREFIX = "/tmp/aws-waf/vpc/"

# Common Linux log locations reported by Wazuh agents
LINUX_LOG_LOCATIONS = (
    "/var/log/syslog",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/messages",
    "/var/log/kern.log",
    "/var/log/cron",
    "/var/log/audit/audit.log",
    "/var/log/daemon.log",
    "/var/log/maillog",
    "/var/log/boot.log",
    "/var/log/firewalld",
    "/var/log/journal",
)


def safe_get(d, *keys):
    """Safely get nested dict values"""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return ""
        cur = cur[k]
    return cur if cur is not None else ""


def parse_json_safe(raw):
    """Safely parse JSON string to dict"""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {}


# ============================================================================
# WAF Action Groups - Flexible action mapping
# ============================================================================

WAF_ACTION_GROUPS = {
    "allowed": {"ALLOW", "PERMIT", "ACCEPT", "PASS"},
    "blocked": {"BLOCK", "DENY", "DROP", "REJECT"},
    "monitor": {"COUNT", "MONITOR", "LOG", "DETECT"}
}

ACTION_GROUP_TO_OUTCOME = {
    "allowed": "allowed",
    "blocked": "blocked",
    "monitor": "allowed"
}


def normalize_action(action: str) -> str:
    return (action or "").strip().upper()


def outcome_from_waf_action(action: str) -> str:
    a = normalize_action(action)

    for group, actions in WAF_ACTION_GROUPS.items():
        if a in actions:
            return ACTION_GROUP_TO_OUTCOME.get(group, "unknown")

    return "unknown"


def extract_user_agent(headers) -> str:
    if not isinstance(headers, list):
        return ""
    for h in headers:
        if isinstance(h, dict) and h.get("name", "").lower() == "user-agent":
            return h.get("value", "")
    return ""


def normalize_waf_event(archive_evt: dict) -> Optional[dict]:
    """
    Normalize AWS WAF event from Wazuh archive.
    Prefer full_log, fallback to data.
    """
    waf = parse_json_safe(archive_evt.get("full_log", ""))

    if not waf:
        data = archive_evt.get("data", {})
        if isinstance(data, dict):
            waf = data

    if not isinstance(waf, dict) or not waf:
        return None

    # Guard: must look like WAF event
    if "httpRequest" not in waf and "webaclId" not in waf and "action" not in waf:
        return None

    action = waf.get("action", "")
    headers = safe_get(waf, "httpRequest", "headers")
    if not isinstance(headers, list):
        headers = []

    normalized = {
        "time": waf.get("timestamp", ""),
        "log_type": "waf",
        "vendor": "aws",

        "action": action.lower(),
        "outcome": outcome_from_waf_action(action),

        "asset_host": waf.get("httpSourceId", ""),
        "correlation_id": safe_get(waf, "httpRequest", "requestId"),

        "network": {
            "source_ip": safe_get(waf, "httpRequest", "clientIp"),
            "source_port": None,
            "country": safe_get(waf, "httpRequest", "country"),
            "destination_ip": safe_get(waf, "httpRequest", "host"),
            "destination_port": None,
            "protocol": safe_get(waf, "httpRequest", "httpVersion"),
            "method": safe_get(waf, "httpRequest", "httpMethod"),
        },

        "message": f"WAF {action} request to {safe_get(waf, 'httpRequest', 'uri')}",
        "maliciousIP": None,

        "waf": {
            "webacl_id": waf.get("webaclId"),
            "http_source_name": waf.get("httpSourceName"),
            "terminating_rule_id": waf.get("terminatingRuleId"),
            "terminating_rule_type": waf.get("terminatingRuleType"),
            "terminating_rule_match_details": waf.get("terminatingRuleMatchDetails", []),
            "labels": waf.get("labels", []),
            "rule_groups": waf.get("ruleGroupList", []),
            "rate_based": waf.get("rateBasedRuleList", []),
            "non_terminating_matching_rules": waf.get("nonTerminatingMatchingRules", []),
            "request_headers_inserted": waf.get("requestHeadersInserted"),
            "response_code_sent": waf.get("responseCodeSent"),

            "uri": safe_get(waf, "httpRequest", "uri"),
            "args": safe_get(waf, "httpRequest", "args"),
            "host_header": safe_get(waf, "httpRequest", "host"),
            "scheme": safe_get(waf, "httpRequest", "scheme"),
            "fragment": safe_get(waf, "httpRequest", "fragment"),
            "user_agent": extract_user_agent(headers),
            "headers": headers,

            "ja3": waf.get("ja3Fingerprint"),
            "ja4": waf.get("ja4Fingerprint"),
            "requestBodySize": waf.get("requestBodySize"),
            "requestBodySizeInspectedByWAF": waf.get("requestBodySizeInspectedByWAF")
        }
    }

    return normalized


# ============================================================================
# VPC Flow
# ============================================================================

def get_protocol_name(protocol_num: int) -> str:
    protocols = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    return protocols.get(protocol_num, str(protocol_num))


def outcome_from_vpc_action(action: str, log_status: str) -> str:
    """
    Convert VPC Flow action + log_status to outcome
    """
    action_upper = (action or "").upper()
    status_upper = (log_status or "").upper()

    outcome_map = {
        ("ACCEPT", "OK"): "allowed",
        ("REJECT", "OK"): "blocked",
        ("ACCEPT", "NODATA"): "allowed",
        ("REJECT", "NODATA"): "blocked",
    }

    if status_upper == "SKIPDATA":
        return "unknown"

    outcome = outcome_map.get((action_upper, status_upper))
    if outcome:
        return outcome

    return "unknown"


def normalize_vpc_flow_event(archive_evt: dict) -> Optional[dict]:
    """
    Normalize AWS VPC Flow log from Wazuh archive
    """
    log_data = archive_evt.get("data", {})
    if not isinstance(log_data, dict) or not log_data:
        log_data = parse_json_safe(archive_evt.get("full_log", ""))

    if not isinstance(log_data, dict) or log_data.get("type") != "aws_vpc_flow":
        return None

    flow = log_data.get("flow", {})
    if not isinstance(flow, dict) or not flow:
        return None

    protocol_num = flow.get("protocol")
    try:
        protocol_num = int(protocol_num) if protocol_num is not None else None
    except Exception:
        protocol_num = None

    normalized = {
        "time": log_data.get("event_timestamp"),
        "log_type": "vpc",
        "vendor": "aws",

        "action": (flow.get("action") or "").lower(),
        "outcome": outcome_from_vpc_action(flow.get("action"), flow.get("log_status")),

        "asset_host": flow.get("interface_id"),
        "correlation_id": log_data.get("event_id"),

        "network": {
            "source_ip": flow.get("srcaddr"),
            "source_port": int(flow.get("srcport")) if flow.get("srcport") not in (None, "", "null") else None,
            "country": None,
            "destination_ip": flow.get("dstaddr"),
            "destination_port": int(flow.get("dstport")) if flow.get("dstport") not in (None, "", "null") else None,
            "protocol": get_protocol_name(protocol_num) if protocol_num is not None else None,
            "method": None
        },

        "message": log_data.get("raw_message"),
        "maliciousIP": None,

        "flow": {
            "version": flow.get("version"),
            "account_id": flow.get("account_id"),
            "interface_id": flow.get("interface_id"),
            "packets": int(flow.get("packets")) if flow.get("packets") not in (None, "", "null") else None,
            "bytes": int(flow.get("bytes")) if flow.get("bytes") not in (None, "", "null") else None,
            "start": flow.get("start"),
            "end": flow.get("end"),
            "action": flow.get("action"),
            "log_status": flow.get("log_status"),
            "owner": log_data.get("owner"),
            "logGroup": log_data.get("logGroup"),
            "logStream": log_data.get("logStream")
        }
    }

    return normalized


# ============================================================================
# Linux
# ============================================================================

LINUX_SEVERITY_MAP = {
    0: "emergency",
    1: "alert",
    2: "critical",
    3: "error",
    4: "warning",
    5: "notice",
    6: "info",
    7: "debug",
}

# Map Wazuh rule level to outcome
def outcome_from_wazuh_level(level) -> str:
    """Convert Wazuh rule level (0-15) to outcome."""
    try:
        lvl = int(level) if level is not None else 0
    except (ValueError, TypeError):
        return "unknown"
    if lvl >= 12:
        return "critical"
    if lvl >= 8:
        return "failure"
    if lvl >= 5:
        return "warning"
    if lvl >= 1:
        return "success"
    return "info"


def classify_linux_action(rule_id, full_log: str, decoder_name: str) -> str:
    """
    Classify the Linux event action based on Wazuh rule_id, decoder name,
    and log content.
    """
    try:
        rid = int(rule_id) if rule_id else 0
    except (ValueError, TypeError):
        rid = 0

    fl = (full_log or "").lower()
    dec = (decoder_name or "").lower()

    # SSH events
    if rid in (5715, 5716):
        return "ssh_login_success"
    if rid in (5710, 5711, 5712):
        return "ssh_login_failed"
    if rid == 5718:
        return "ssh_key_auth"
    if rid in (5701, 5702, 5703, 5704, 5705, 5706, 5707, 5709):
        return "ssh_event"
    if rid in (5551,):
        return "ssh_session_opened"
    if rid in (5502,):
        return "ssh_session_closed"
    if "sshd" in dec or "sshd" in fl:
        if "accepted" in fl:
            return "ssh_login_success"
        if "failed" in fl or "invalid user" in fl:
            return "ssh_login_failed"
        if "disconnected" in fl or "closed" in fl:
            return "ssh_disconnect"
        return "ssh_event"

    # Sudo events
    if rid in (5400, 5401, 5402, 5403, 5404, 5405):
        return "sudo_executed"
    if "sudo" in dec or "sudo" in fl:
        if "command" in fl:
            return "sudo_executed"
        if "authentication failure" in fl or "incorrect password" in fl:
            return "sudo_auth_failed"
        return "sudo_event"

    # User/group management
    if rid in (5901, 5902):
        return "user_created"
    if rid in (5903, 5904):
        return "user_deleted"
    if rid in (5905, 5906):
        return "group_changed"
    if rid in (5907, 5908):
        return "user_modified"
    if "useradd" in fl or "adduser" in fl:
        return "user_created"
    if "userdel" in fl or "deluser" in fl:
        return "user_deleted"
    if "passwd" in fl or "chpasswd" in fl:
        return "password_changed"
    if "groupadd" in fl or "groupdel" in fl or "groupmod" in fl:
        return "group_changed"
    if "usermod" in fl:
        return "user_modified"

    # PAM authentication
    if "pam" in dec or "pam_unix" in fl:
        if "authentication failure" in fl:
            return "pam_auth_failed"
        if "session opened" in fl:
            return "pam_session_opened"
        if "session closed" in fl:
            return "pam_session_closed"
        return "pam_event"

    # Cron
    if "cron" in dec or "cron" in fl or rid in (5801, 5802, 5803, 5804, 5805):
        return "cron_job"

    # Systemd
    if "systemd" in fl:
        if "started" in fl:
            return "service_started"
        if "stopped" in fl:
            return "service_stopped"
        if "failed" in fl:
            return "service_failed"
        return "systemd_event"

    # Firewall
    if "iptables" in fl or "nftables" in fl or "firewalld" in fl:
        if "drop" in fl or "reject" in fl or "denied" in fl:
            return "firewall_block"
        if "accept" in fl:
            return "firewall_allow"
        return "firewall_event"

    # Audit
    if "audit" in dec or "auditd" in fl:
        return "audit_event"

    # Kernel
    if "kernel" in dec or rid in (5100, 5101, 5102, 5103, 5104):
        return "kernel_event"

    # Package management
    if any(pkg in fl for pkg in ("apt", "yum", "dnf", "dpkg", "rpm")):
        return "package_management"

    return "syslog_event"


def extract_linux_source_ip(full_log: str, data: dict) -> str:
    """Extract source IP from Linux log content."""
    import re

    # Try Wazuh decoded data first
    if isinstance(data, dict):
        for key in ("srcip", "src_ip", "srcaddr", "ip", "addr"):
            val = data.get(key)
            if val:
                return str(val)

    # Try to extract from log message
    if full_log:
        # Common patterns: "from X.X.X.X", "rhost=X.X.X.X", "SRC=X.X.X.X"
        patterns = [
            r'from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'rhost=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'SRC=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'src=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        ]
        for pattern in patterns:
            match = re.search(pattern, full_log)
            if match:
                return match.group(1)

    return ""


def extract_linux_user(full_log: str, data: dict) -> str:
    """Extract username from Linux log content."""
    import re

    # Try Wazuh decoded data first
    if isinstance(data, dict):
        for key in ("dstuser", "srcuser", "user", "acct", "uid"):
            val = data.get(key)
            if val:
                return str(val)

    # Try to extract from log message
    if full_log:
        patterns = [
            r'user[= ](\S+)',
            r'for\s+(?:invalid\s+user\s+)?(\S+)',
            r'acct="?(\S+?)"?\s',
            r'USER=(\S+)',
            r'COMMAND=(\S+)',
        ]
        for pattern in patterns:
            match = re.search(pattern, full_log, re.IGNORECASE)
            if match:
                return match.group(1)

    return ""


def extract_linux_port(full_log: str, data: dict) -> str:
    """Extract port from Linux log content."""
    import re

    if isinstance(data, dict):
        for key in ("srcport", "src_port", "dstport", "dst_port", "port"):
            val = data.get(key)
            if val:
                return str(val)

    if full_log:
        match = re.search(r'port\s+(\d+)', full_log)
        if match:
            return match.group(1)

    return ""


def extract_linux_process(full_log: str, data: dict) -> str:
    """Extract process/program name from Linux log."""
    import re

    if isinstance(data, dict):
        for key in ("program_name", "process", "exe"):
            val = data.get(key)
            if val:
                return str(val)

    if full_log:
        # syslog format: "hostname program[pid]: message"
        match = re.search(r'\S+\s+(\S+?)\[\d+\]:', full_log)
        if match:
            return match.group(1)

    return ""


def normalize_linux_event(archive_evt: dict) -> Optional[dict]:
    """
    Normalize Linux syslog/auth event from Wazuh archive.
    Handles: SSH, sudo, PAM, cron, systemd, user management,
    firewall (iptables/nftables), audit, and generic syslog.
    """
    full_log_raw = archive_evt.get("full_log", "")
    data = archive_evt.get("data", {})
    if not isinstance(data, dict):
        data = {}

    rule = archive_evt.get("rule", {})
    if not isinstance(rule, dict):
        rule = {}

    agent = archive_evt.get("agent", {})
    if not isinstance(agent, dict):
        agent = {}

    decoder = archive_evt.get("decoder", {})
    if not isinstance(decoder, dict):
        decoder = {}

    predecoder = archive_evt.get("predecoder", {})
    if not isinstance(predecoder, dict):
        predecoder = {}

    # Extract timestamp - prefer predecoder timestamp, fallback to archive timestamp
    timestamp = (
        predecoder.get("timestamp")
        or archive_evt.get("timestamp")
        or ""
    )

    # Convert ISO timestamp to epoch ms if possible
    event_time = None
    if timestamp:
        try:
            from datetime import datetime as dt
            if isinstance(timestamp, (int, float)):
                event_time = int(float(timestamp) * 1000)
            else:
                ts_str = str(timestamp)
                # Try ISO format
                try:
                    parsed = dt.fromisoformat(ts_str.replace("Z", "+00:00"))
                    event_time = int(parsed.timestamp() * 1000)
                except Exception:
                    pass
        except Exception:
            pass

    rule_id = rule.get("id", "")
    rule_level = rule.get("level", 0)
    rule_description = rule.get("description", "")
    decoder_name = decoder.get("name", "")
    decoder_parent = decoder.get("parent", "")

    action = classify_linux_action(rule_id, full_log_raw, decoder_name)
    outcome = outcome_from_wazuh_level(rule_level)

    source_ip = extract_linux_source_ip(full_log_raw, data)
    user = extract_linux_user(full_log_raw, data)
    port_str = extract_linux_port(full_log_raw, data)
    process_name = extract_linux_process(full_log_raw, data)

    source_port = None
    if port_str:
        try:
            source_port = int(port_str)
        except (ValueError, TypeError):
            pass

    # Build hostname from agent or predecoder
    hostname = (
        predecoder.get("hostname")
        or agent.get("name")
        or agent.get("ip")
        or ""
    )

    # Build message: prefer rule description, fallback to first line of full_log
    message = rule_description
    if not message and full_log_raw:
        first_line = full_log_raw.split("\n")[0].strip()
        if len(first_line) > 200:
            first_line = first_line[:200] + "..."
        message = first_line

    # Map Wazuh rule groups to category
    rule_groups = rule.get("groups", [])
    if isinstance(rule_groups, str):
        rule_groups = [rule_groups]
    if not isinstance(rule_groups, list):
        rule_groups = []

    normalized = {
        "time": event_time,
        "log_type": "linux",
        "vendor": "Linux",

        "action": action,
        "outcome": outcome,

        "asset_host": hostname,
        "correlation_id": "",

        "network": {
            "source_ip": source_ip,
            "source_port": source_port,
            "country": "",
            "destination_ip": agent.get("ip", ""),
            "destination_port": None,
            "protocol": "",
            "method": ""
        },

        "message": message,
        "maliciousIP": None,

        "waf": "",
        "flow": "",
        "winEvent": "",

        "linuxEvent": {
            "hostname": hostname,
            "program": predecoder.get("program_name") or process_name,
            "pid": data.get("pid") or "",
            "user": user,
            "ruleID": str(rule_id),
            "ruleLevel": rule_level,
            "ruleDescription": rule_description,
            "ruleGroups": rule_groups,
            "decoderName": decoder_name,
            "decoderParent": decoder_parent,
            "location": archive_evt.get("location", ""),
            "fullLog": full_log_raw[:500] if full_log_raw else "",
        }
    }

    return normalized


# ============================================================================
# Windows
# ============================================================================

LOGON_TYPES = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}

WINDOWS_EVENT_OUTCOMES = {
    4624: "success",
    4625: "failure",
    4634: "success",
    4647: "success",
    4648: "success",
    4720: "success",
    4722: "success",
    4723: "failure",
    4724: "success",
    4725: "success",
    4726: "success",
    4738: "success",
    4740: "success",
    4767: "success",
    4688: "success",
    4689: "success",
    4663: "success",
    4656: "success",
    4658: "success",
    4719: "success",
    4739: "success",
    4672: "success",
    4673: "failure",
}


def outcome_windows_event(event_id: str) -> str:
    try:
        eid = int(event_id) if event_id else 0
        return WINDOWS_EVENT_OUTCOMES.get(eid, "unknown")
    except (ValueError, TypeError):
        return "unknown"


def extract_first_sentence(message: str) -> str:
    if not message:
        return ""

    msg = message.strip()
    if msg.startswith('"') and msg.endswith('"'):
        msg = msg[1:-1]

    for separator in ['.\\r\\n', '.\r\n', '.\\n', '.\n', '. ']:
        if separator in msg:
            first_part = msg.split(separator)[0]
            return first_part.strip() + '.'

    for separator in ['\\r\\n', '\r\n', '\\n', '\n']:
        if separator in msg:
            first_line = msg.split(separator)[0]
            return first_line.strip()

    return msg.strip()


def normalize_windows_event(archive_evt: dict) -> Optional[dict]:
    full_log_raw = archive_evt.get("full_log", "")
    win_data = None

    try:
        if full_log_raw and isinstance(full_log_raw, str):
            parsed_log = json.loads(full_log_raw)
            win_data = parsed_log.get("win", {})
    except Exception:
        pass

    if not win_data:
        data = archive_evt.get("data", {})
        if isinstance(data, dict):
            win_data = data.get("win", {})

    if not win_data:
        return None

    system = win_data.get("system", {})
    eventdata = win_data.get("eventdata", {})
    agent = archive_evt.get("agent", {})

    normalized = {
        "time": system.get("systemTime"),
        "log_type": "win",
        "vendor": "Microsoft",
        "action": system.get("eventID", ""),
        "outcome": outcome_windows_event(system.get("eventID", "")),
        "asset_host": system.get("computer", ""),
        "correlation_id": system.get("correlation", {}).get("activityID", "") if isinstance(system.get("correlation"), dict) else "",
        "network": {
            "source_ip": eventdata.get("ipAddress") or eventdata.get("sourceNetworkAddress") or eventdata.get("workstationName") or "",
            "source_port": eventdata.get("ipPort") or eventdata.get("sourcePort") or "",
            "country": "",
            "destination_ip": agent.get("ip", ""),
            "destination_port": "",
            "protocol": "",
            "method": ""
        },
        "message": extract_first_sentence(system.get("message", "")),
        "maliciousIP": "",
        "waf": "",
        "flow": "",
        "winEvent": {
            "providerName": system.get("providerName", ""),
            "channel": system.get("channel", ""),
            "eventID": system.get("eventID", ""),
            "logonType": LOGON_TYPES.get(eventdata.get("logonType", ""), eventdata.get("logonType", "")),
            "processID": eventdata.get("processId", ""),
            "processName": eventdata.get("processName", ""),
            "subjectUserSid": eventdata.get("subjectUserSid", ""),
            "subjectUserName": eventdata.get("subjectUserName", ""),
            "subjectDomainName": eventdata.get("subjectDomainName", ""),
            "subjectLogonId": eventdata.get("subjectLogonId", ""),
            "targetUserSid": eventdata.get("targetUserSid", ""),
            "targetUserName": eventdata.get("targetUserName", ""),
            "targetDomainName": eventdata.get("targetDomainName", ""),
            "targetLogonId": eventdata.get("targetLogonId", ""),
            "logonProcessName": eventdata.get("logonProcessName", ""),
            "authenticationPackageName": eventdata.get("authenticationPackageName", ""),
            "workstationName": eventdata.get("workstationName", ""),
            "logonGuid": eventdata.get("logonGuid", ""),
        }
    }

    return normalized


# ============================================================================
# Router
# ============================================================================

def _is_linux_event(archive_evt: dict) -> bool:
    """
    Detect if a Wazuh archive event originates from a Linux host.
    Uses multiple heuristics: location path, decoder, agent OS, rule groups.
    """
    location = archive_evt.get("location", "")
    if isinstance(location, str):
        for prefix in LINUX_LOG_LOCATIONS:
            if location.startswith(prefix):
                return True

    # Check decoder name for Linux-specific decoders
    decoder = archive_evt.get("decoder", {})
    if isinstance(decoder, dict):
        decoder_name = (decoder.get("name") or "").lower()
        decoder_parent = (decoder.get("parent") or "").lower()
        linux_decoders = (
            "sshd", "sudo", "pam", "cron", "su", "syslog",
            "systemd", "iptables", "nftables", "auditd",
            "useradd", "userdel", "groupadd", "groupdel",
            "passwd", "kernel", "dpkg", "yum", "apt",
            "proftpd", "vsftpd", "postfix", "dovecot",
            "firewalld", "journald",
        )
        if decoder_name in linux_decoders or decoder_parent in linux_decoders:
            return True

    # Check agent OS platform
    agent = archive_evt.get("agent", {})
    if isinstance(agent, dict):
        agent_os = safe_get(agent, "os", "platform") or safe_get(agent, "os", "name") or ""
        if isinstance(agent_os, str) and any(
            kw in agent_os.lower() for kw in ("linux", "ubuntu", "centos", "debian", "rhel", "fedora", "suse", "amazon")
        ):
            return True

    # Check rule groups for Linux-related groups
    rule = archive_evt.get("rule", {})
    if isinstance(rule, dict):
        groups = rule.get("groups", [])
        if isinstance(groups, str):
            groups = [groups]
        if isinstance(groups, list):
            linux_groups = {
                "syslog", "sshd", "authentication_success", "authentication_failed",
                "pam", "sudo", "cron", "firewall", "audit", "systemd",
                "linux", "local", "adduser", "account_changed",
            }
            for g in groups:
                if isinstance(g, str) and g.lower() in linux_groups:
                    return True

    return False


def normalize_event(archive_evt: dict) -> Optional[dict]:
    """
    Unified normalization function
    Detects log type and routes to appropriate normalizer
    """
    location = archive_evt.get("location", "")
    data = archive_evt.get("data", {})
    full_log_raw = archive_evt.get("full_log", "")
    parsed_full_log = parse_json_safe(full_log_raw)

    # 1. Route by real location in archives
    if isinstance(location, str) and location.startswith(WAF_LOCATION_PREFIX):
        return normalize_waf_event(archive_evt)

    if isinstance(location, str) and location.startswith(VPC_LOCATION_PREFIX):
        return normalize_vpc_flow_event(archive_evt)

    # 2. Route by data field
    if isinstance(data, dict):
        # VPC
        if data.get("type") == "aws_vpc_flow":
            return normalize_vpc_flow_event(archive_evt)

        # WAF
        if "httpRequest" in data and "action" in data:
            return normalize_waf_event(archive_evt)

        # Windows
        if "win" in data:
            return normalize_windows_event(archive_evt)

    # 3. Route by full_log
    if isinstance(parsed_full_log, dict):
        if parsed_full_log.get("type") == "aws_vpc_flow":
            return normalize_vpc_flow_event(archive_evt)

        if "httpRequest" in parsed_full_log and "action" in parsed_full_log:
            return normalize_waf_event(archive_evt)

        if "win" in parsed_full_log:
            return normalize_windows_event(archive_evt)

    # 4. Route Linux events (checked after specific types to avoid false positives)
    if _is_linux_event(archive_evt):
        return normalize_linux_event(archive_evt)

    return None


def follow_file(path):
    """
    Robust file follower (tail -f style)
    - Reads by chunks and yields only COMPLETE lines
    - First open: seek END
    - On rotation/truncate: seek START
    """
    f = None
    last_inode = None
    first_open = True
    buf = ""

    while True:
        try:
            st = os.stat(path)
            inode = st.st_ino

            if f is None or inode != last_inode:
                if f:
                    try:
                        f.close()
                    except Exception:
                        pass
                f = open(path, "r", encoding="utf-8", errors="replace")
                last_inode = inode
                buf = ""

                if first_open:
                    f.seek(0, os.SEEK_END)
                    first_open = False
                else:
                    f.seek(0, os.SEEK_SET)

            if st.st_size < f.tell():
                f.seek(0, os.SEEK_SET)
                buf = ""

            chunk = f.read(4096)
            if not chunk:
                time.sleep(0.02)
                continue

            buf += chunk

            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                yield line

        except FileNotFoundError:
            time.sleep(0.2)
        except Exception:
            time.sleep(0.2)


def main():
    """
    Main function - tail Wazuh archive and normalize logs
    """
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    stats = {
        "waf": 0,
        "vpc": 0,
        "windows": 0,
        "linux": 0,
        "skipped": 0,
        "errors": 0
    }

    TYPE_MAP = {
        "waf": "waf",
        "vpc": "vpc",
        "win": "windows",
        "linux": "linux"
    }

    with open(OUTPUT_PATH, "a", encoding="utf-8") as out:
        for line in follow_file(ARCHIVES_PATH):
            if not line.strip():
                continue

            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                stats["errors"] += 1
                continue

            norm = normalize_event(evt)

            if not norm:
                stats["skipped"] += 1
                continue

            out.write(json.dumps(norm, ensure_ascii=False) + "\n")
            out.flush()

            log_type = norm.get("log_type")
            mapped = TYPE_MAP.get(log_type)

            if mapped:
                stats[mapped] += 1
            else:
                stats["skipped"] += 1


if __name__ == "__main__":
    main()
