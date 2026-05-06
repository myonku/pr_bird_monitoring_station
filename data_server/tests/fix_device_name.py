"""
Fix device_name occurrences in MongoDB collections:
- change "测试设备A" -> "测试站点 A"
Targets:
- edge_event_envelopes (top-level `device_name`, nested `payload_body.context.device_name`)
- monitoring_records (top-level `device_name`)

Run from project root or data_server directory; reads data_server/settings.toml for Mongo settings.
"""
from pathlib import Path
import sys
import pprint

OLD = "测试设备A"
NEW = "测试站点 A"

# parse settings.toml
settings_path = Path(__file__).resolve().parent.parent / "settings.toml"
if not settings_path.exists():
    print("settings.toml not found:", settings_path)
    sys.exit(2)

try:
    import tomllib as toml
except Exception:
    try:
        import toml # type: ignore
    except Exception:
        print("Please install toml or use Python 3.11+ for tomllib")
        sys.exit(2)

cfg = toml.loads(settings_path.read_text(encoding="utf-8"))
mongo_cfg = cfg.get("mongo", {})
if not mongo_cfg:
    print("mongo config missing in settings.toml")
    sys.exit(2)

host = mongo_cfg.get("HOST", "127.0.0.1")
port = mongo_cfg.get("PORT", 27017)
user = mongo_cfg.get("USER")
password = mongo_cfg.get("PASSWORD")
dbname = mongo_cfg.get("DATABASE", "bms_test")
authsource = mongo_cfg.get("AUTHSOURCE", "admin")
direct = mongo_cfg.get("DIRECTCONNECTION", True)
tls = mongo_cfg.get("TLS", False)

from pymongo import MongoClient

if user and password:
    uri = f"mongodb://{user}:{password}@{host}:{port}/?authSource={authsource}"
else:
    uri = f"mongodb://{host}:{port}/"

if direct:
    uri += "&directConnection=true"
if tls:
    uri += "&tls=true"

print("Connecting to Mongo:", uri)
client = MongoClient(uri)
db = client[dbname]

edge_coll = db["edge_event_envelopes"]
mon_coll = db["monitoring_records"]

result = {}

# top-level updates
r1 = edge_coll.update_many({"device_name": OLD}, {"$set": {"device_name": NEW}})
result['edge.device_name_updated'] = r1.modified_count
r2 = mon_coll.update_many({"device_name": OLD}, {"$set": {"device_name": NEW}})
result['monitor.device_name_updated'] = r2.modified_count

# nested payload_body.context.device_name in edge_events
r3 = edge_coll.update_many({"payload_body.context.device_name": OLD}, {"$set": {"payload_body.context.device_name": NEW}})
result['edge.payload_context_updated'] = r3.modified_count

# scan metadata dictionaries and replace direct-matching values
def scan_and_fix(coll, coll_name):
    changed = 0
    cursor = coll.find({"metadata": {"$exists": True}}, {"metadata": 1})
    for doc in cursor:
        meta = doc.get("metadata") or {}
        updated = False
        for k, v in list(meta.items()):
            if v == OLD:
                meta[k] = NEW
                updated = True
        if updated:
            coll.update_one({"_id": doc["_id"]}, {"$set": {"metadata": meta}})
            changed += 1
    result[f"{coll_name}.metadata_fixed"] = changed

scan_and_fix(edge_coll, "edge")
scan_and_fix(mon_coll, "monitor")

print("Summary of updates:")
pprint.pprint(result)

print("Done.")

if any(v > 0 for v in result.values()):
    sys.exit(0)
else:
    sys.exit(1)
