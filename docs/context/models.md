# Model field reference

## HoneyEvent
ip (GenericIPAddressField, indexed)
path (CharField 2048)
method (CharField 8)
headers (JSONField)           # all request headers
body (JSONField, null)        # truncated at 64KB
ja3_hash (CharField 64, null)
user_agent (TextField)
decoy_type (CharField 50)     # admin/env/wpAdmin/api/custom
timestamp (DateTimeField auto_now_add, db_index)
attacker (FK AttackerProfile, null, on_delete SET_NULL)
enriched (BooleanField default False)

## AttackerProfile
ip (GenericIPAddressField, unique, primary lookup)
asn (CharField 20, null)
org (CharField 200, null)
country_code (CharField 2, null)
country (CharField 100, null)
city (CharField 100, null)
lat (DecimalField 9,6, null)
lon (DecimalField 9,6, null)
first_seen (DateTimeField auto_now_add)
last_seen (DateTimeField auto_now)
event_count (PositiveIntegerField default 0)
threat_score (SmallIntegerField default 0)  # 0-100
tags (ArrayField CharField, default=list)   # ttp tags
is_known_scanner (BooleanField default False)

## CanaryToken
token_id (UUIDField default uuid4, unique)
token_type (CharField: url/email/dns/aws_key/file)
label (CharField 200)
created_by (FK User)
triggered (BooleanField default False)
triggered_at (DateTimeField null)
trigger_ip (GenericIPAddressField null)

## AlertRule
name (CharField 200)
condition (JSONField)         # {"field": "threat_score", "op": "gt", "value": 80}
notifier_type (CharField: slack/email/webhook)
notifier_config (JSONField)   # {"url": "..."} or {"to": "..."}
enabled (BooleanField default True)
last_fired (DateTimeField null)

## ThreatFeedEntry
ip (GenericIPAddressField, db_index)
source (CharField 50)         # abuseipdb/virustotal
confidence (SmallIntegerField)
category (CharField 100, null)
expires_at (DateTimeField, db_index)  # Celery beat purges expired