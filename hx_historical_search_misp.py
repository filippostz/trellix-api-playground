import time
import requests
import json
import sys
from datetime import datetime, timedelta, timezone
from pymisp import PyMISP, MISPEvent
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ==========================================
#              CONFIGURATION
# ==========================================

# --- MISP Config ---
MISP_URL = 'https://your-misp-instance.com'
MISP_KEY = 'YOUR_MISP_API_KEY'
MISP_VERIFY_CERT = False

# Dynamic Hunt Configuration: Tag Name -> Lookback Hours
HUNT_CONFIG = {
    'hunt_1': 24,  # 1 Day
    'hunt_7': 168,  # 7 Days
    'hunt_30': 720  # 30 Days
}

TAG_ON_MATCH = 'prevalent'  # Tag if found
TAG_ON_CLEAN = 'checked'  # Tag if NOT found

# --- Trellix HX Config ---
HX_BASE_URL = "https://your-hx-instance.com:3000"
HX_API_TOKEN = ""  # Optional: Hardcode token here
HX_USERNAME = "api_username"
HX_PASSWORD = "api_password"

# --- Polling Config ---
CHECK_INTERVAL = 60  # Seconds between MISP checks
HX_POLL_INTERVAL = 5  # Seconds between HX status checks
HX_MAX_RETRIES = 60  # Max polling attempts for HX search
HX_QUERY_BATCH_SIZE = 50  # Max number of IOCs to search in a single API call


# ==========================================
#          TRELLIX HX FUNCTIONS
# ==========================================

def get_hx_token(base_url, username, password, api_token=None):
    if api_token and api_token.strip():
        return api_token

    if username and password:
        token_url = f"{base_url}/hx/api/v3/token"
        try:
            response = requests.head(token_url, auth=(username, password), verify=False)
            response.raise_for_status()
            token = response.headers.get('X-FeApi-Token')
            if token: return token
        except Exception as e:
            print(f"[X] HX Auth failed: {e}")
            return None
    return None


def search_hx_bulk(base_url, token, hash_batch, t_start_iso, t_end_iso):
    """Initiates a SINGLE historical search for a batch of hashes."""
    search_url = f"{base_url}/hx/api/plugins/historical-search/v1/search"

    conditions = []
    for val, h_type in hash_batch:
        field = f"fileAttributes.{h_type}"
        conditions.append(f"{field}='{val}'")

    full_condition = " OR ".join(conditions)

    payload = {
        "data": {
            "type": "search",
            "attributes": {
                "query": {
                    "condition": full_condition,
                    "startTime": t_start_iso,
                    "endTime": t_end_iso
                }
            }
        }
    }
    headers = {'X-FeApi-Token': token, 'Content-Type': 'application/json'}

    try:
        res = requests.post(search_url, headers=headers, json=payload, verify=False, params={'maxResults': 2000})
        res.raise_for_status()
        return res.json().get('data', {}).get('id')
    except Exception as e:
        print(f"[X] HX Bulk Search init failed: {e}")
        return None


def wait_and_get_results(base_url, token, search_id):
    status_url = f"{base_url}/hx/api/plugins/historical-search/v1/status/{search_id}"
    results_url = f"{base_url}/hx/api/plugins/historical-search/v1/results/{search_id}"
    headers = {'X-FeApi-Token': token, 'Accept': 'application/json'}

    # print(f"    ... Polling HX Job ID: {search_id}")

    for _ in range(HX_MAX_RETRIES):
        try:
            res = requests.get(status_url, headers=headers, verify=False)
            res.raise_for_status()
            status = res.json().get('data', {}).get('attributes', {}).get('status')

            if status == 'FINISHED':
                res_data = requests.get(results_url, headers=headers, params={'page[limit]': 500}, verify=False)
                res_data.raise_for_status()
                items = res_data.json().get('data', {}).get('attributes', {}).get('items', [])
                return items
            elif status in ['FAILED', 'STOPPED', 'EXPIRED']:
                print(f"    [!] HX Search stopped with status: {status}")
                return []
            time.sleep(HX_POLL_INTERVAL)
        except Exception:
            return []
    return []


# ==========================================
#          HELPER FUNCTIONS
# ==========================================

def init_misp():
    return PyMISP(MISP_URL, MISP_KEY, ssl=MISP_VERIFY_CERT, debug=False)


def verify_tags_exist(misp):
    print("[*] Verifying required tags on MISP...")
    missing_tags = []

    all_required_tags = list(HUNT_CONFIG.keys()) + [TAG_ON_MATCH, TAG_ON_CLEAN]

    for tag_name in all_required_tags:
        tag_found = False
        try:
            res = misp.search_tags(tag_name, pythonify=True)
            if res:
                for t in res:
                    found_name = t.name if hasattr(t, 'name') else t.get('name', '')
                    if found_name.lower() == tag_name.lower():
                        tag_found = True
                        break
            if not tag_found: missing_tags.append(tag_name)
        except Exception:
            missing_tags.append(tag_name)

    if missing_tags:
        print(f"[!] CRITICAL: Missing tags in MISP: {missing_tags}")
        return False
    print("    -> All required tags found.")
    return True


def has_tag(item, target_tag_name):
    """Generic check if an item has a specific tag (case-insensitive)."""
    if not hasattr(item, 'tags') or not item.tags: return False
    target = target_tag_name.lower()
    for t in item.tags:
        name = t.name if hasattr(t, 'name') else t.get('name', '')
        if name.lower() == target: return True
    return False


def get_hunt_tag_info(item):
    if not hasattr(item, 'tags') or not item.tags: return None, None
    for t in item.tags:
        t_name = t.name if hasattr(t, 'name') else t.get('name', '')
        for cfg_tag, hours in HUNT_CONFIG.items():
            if t_name.lower() == cfg_tag.lower():
                return cfg_tag, hours
    return None, None


def extract_scannable_hashes(attributes):
    res = []
    for attr in attributes:
        if attr.type not in ['md5', 'sha1', 'sha256']:
            continue
        if has_tag(attr, TAG_ON_CLEAN):
            continue
        res.append((attr.value, attr.type))
    return res


def process_hashes_and_hunt(misp, hx_token, hash_list, entity_uuid, event_uuid, scope_name, hunt_tag, lookback_hours):
    hash_list = list(set(hash_list))

    # Calculate Time Windows
    dt_end = datetime.now(timezone.utc)
    dt_start = dt_end - timedelta(hours=lookback_hours)

    api_end = dt_end.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    api_start = dt_start.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    readable_end = dt_end.strftime("%Y-%m-%d %H:%M")
    readable_start = dt_start.strftime("%Y-%m-%d %H:%M")
    current_run_date = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Format window string for display (e.g. "1 day" or "7 days")
    if lookback_hours % 24 == 0:
        window_str = f"{lookback_hours // 24} days"
    else:
        window_str = f"{lookback_hours} hours"

    print(
        f"    -> Scope: {scope_name.upper()} {entity_uuid} | Tag: {hunt_tag} ({window_str}) | Hashes: {len(hash_list)}")

    # --- START TIMER ---
    start_timer = time.time()

    found_map = {}

    # --- BATCH PROCESSING ---
    for i in range(0, len(hash_list), HX_QUERY_BATCH_SIZE):
        batch = hash_list[i: i + HX_QUERY_BATCH_SIZE]
        print(f"       Processing Batch {i // HX_QUERY_BATCH_SIZE + 1} ({len(batch)} hashes)...")

        job_id = search_hx_bulk(HX_BASE_URL, hx_token, batch, api_start, api_end)

        if job_id:
            results = wait_and_get_results(HX_BASE_URL, hx_token, job_id)

            if results:
                for item in results:
                    host = item.get('output', {}).get('host', 'Unknown')
                    file_attrs = item.get('output', {}).get('fileAttributes', {})

                    for h_val, h_type in batch:
                        event_hash_val = file_attrs.get(h_type)
                        if event_hash_val and event_hash_val.lower() == h_val.lower():
                            if h_val not in found_map:
                                found_map[h_val] = set()
                            found_map[h_val].add(host)
        else:
            print("       [ERROR] Batch search failed.")

    # --- END TIMER ---
    end_timer = time.time()
    duration = end_timer - start_timer

    # --- RESULTS AGGREGATION ---
    found_lines = []
    not_found_lines = []

    for val, h_type in hash_list:
        if val in found_map:
            hosts = sorted(list(found_map[val]))
            hosts_str = ", ".join(hosts[:10])
            if len(hosts) > 10: hosts_str += f" (+{len(hosts) - 10} others)"
            found_lines.append(f"{val} on {hosts_str}")
        else:
            not_found_lines.append(val)

    # --- ACTION LOGIC ---
    try:
        misp.untag(entity_uuid, hunt_tag)
    except Exception as e:
        print(f"    [X] Failed to remove tag: {e}")
        return False

    # Comment Construction
    comment_header = f"Hunt ({scope_name})\nSearched prevalence between {readable_start} and {readable_end} for {len(hash_list)} IOCs on {current_run_date}"
    comment_parts = [comment_header]

    if found_lines:
        comment_parts.append("Found:")
        comment_parts.extend(found_lines)

    if not_found_lines:
        comment_parts.append("Not found:")
        comment_parts.extend(not_found_lines)

    final_comment = "\n".join(comment_parts)
    if len(final_comment) > 65000: final_comment = final_comment[:65000] + "\n...(truncated)"

    # Tags
    if found_lines:
        print(
            f"    -> MATCHES FOUND ({len(found_lines)}). Applying '{TAG_ON_MATCH}'. (Scanned {len(hash_list)} IOCs for {window_str} history in {duration:.2f}s)")
        try:
            misp.tag(entity_uuid, TAG_ON_MATCH)
            misp.add_attribute(event_uuid, {
                'type': 'text', 'value': final_comment, 'category': 'Internal reference', 'to_ids': False,
                'comment': 'Auto-Hunt Report'
            })
            return True
        except Exception as e:
            print(f"    [X] Error tagging match: {e}")
            return False
    else:
        print(
            f"    -> CLEAN. Applying '{TAG_ON_CLEAN}'. (Scanned {len(hash_list)} IOCs for {window_str} history in {duration:.2f}s)")
        try:
            misp.tag(entity_uuid, TAG_ON_CLEAN)
            misp.add_attribute(event_uuid, {
                'type': 'text', 'value': final_comment, 'category': 'Internal reference', 'to_ids': False,
                'comment': 'Auto-Hunt Report'
            })
            return True
        except Exception as e:
            print(f"    [X] Error tagging clean: {e}")
            return False


# ==========================================
#            MAIN LOGIC
# ==========================================

def main():
    try:
        misp = init_misp()
        print(f"[*] Connected to MISP at {MISP_URL}")
    except Exception as e:
        print(f"[X] Failed to connect to MISP: {e}")
        return

    if not verify_tags_exist(misp):
        sys.exit(1)

    print(f"[*] Listening for hunt tags: {list(HUNT_CONFIG.keys())}...")

    event_timestamp_cache = {}
    last_check_time = datetime.now(timezone.utc)

    while True:
        try:
            current_time = datetime.now(timezone.utc)
            search_timestamp = last_check_time - timedelta(seconds=10)
            timestamp_filter = search_timestamp.strftime('%Y-%m-%d %H:%M:%S')

            response = misp.search(
                tags=list(HUNT_CONFIG.keys()),
                timestamp=timestamp_filter,
                pythonify=True
            )

            if response:
                hx_token = get_hx_token(HX_BASE_URL, HX_USERNAME, HX_PASSWORD, HX_API_TOKEN)

                if not hx_token:
                    print("[!] HX Auth failed. Skipping batch.")
                else:
                    for event in response:
                        event_id_str = str(event.id)
                        event_uuid = event.uuid
                        current_event_ts = str(event.timestamp)

                        if event_id_str in event_timestamp_cache:
                            if event_timestamp_cache[event_id_str] == current_event_ts:
                                continue

                        event_timestamp_cache[event_id_str] = current_event_ts

                        print(f"\n[!] Inspecting Event {event_id_str}: {event.info}")

                        action_taken = False

                        # 1. Event Level Check
                        e_tag, e_hours = get_hunt_tag_info(event)
                        if e_tag:
                            print(f"    [MATCH] Event-level tag '{e_tag}' found. Scanning EVERYTHING.")
                            all_hashes = []
                            if hasattr(event, 'attributes'):
                                all_hashes.extend(extract_scannable_hashes(event.attributes))
                            if hasattr(event, 'objects'):
                                for obj in event.objects:
                                    if hasattr(obj, 'attributes'):
                                        all_hashes.extend(extract_scannable_hashes(obj.attributes))

                            if all_hashes:
                                process_hashes_and_hunt(misp, hx_token, all_hashes, event_uuid, event_uuid, 'Event',
                                                        e_tag, e_hours)
                                action_taken = True
                            else:
                                print("    [!] No unchecked hashes found in this event.")
                                try:
                                    misp.untag(event_uuid, e_tag)
                                except:
                                    pass

                        else:
                            # 2. Object & Attribute Level Checks
                            if hasattr(event, 'objects'):
                                for obj in event.objects:
                                    o_tag, o_hours = get_hunt_tag_info(obj)
                                    if o_tag:
                                        print(f"    [MATCH] Object {obj.name} tagged '{o_tag}'.")
                                        obj_hashes = []
                                        if hasattr(obj, 'attributes'):
                                            obj_hashes.extend(extract_scannable_hashes(obj.attributes))

                                        if obj_hashes:
                                            process_hashes_and_hunt(misp, hx_token, obj_hashes, obj.uuid, event_uuid,
                                                                    'Object', o_tag, o_hours)
                                            action_taken = True
                                        else:
                                            print(f"    [!] Object has no new hashes.")
                                            try:
                                                misp.untag(obj.uuid, o_tag)
                                            except:
                                                pass
                                    else:
                                        if hasattr(obj, 'attributes'):
                                            for attr in obj.attributes:
                                                a_tag, a_hours = get_hunt_tag_info(attr)
                                                if attr.type in ['md5', 'sha1', 'sha256'] and a_tag:
                                                    print(
                                                        f"    [MATCH] Object Attribute {attr.value} tagged '{a_tag}'.")
                                                    target_hash = [(attr.value, attr.type)]
                                                    process_hashes_and_hunt(misp, hx_token, target_hash, attr.uuid,
                                                                            event_uuid, 'Attribute', a_tag, a_hours)
                                                    action_taken = True

                            if hasattr(event, 'attributes'):
                                for attr in event.attributes:
                                    a_tag, a_hours = get_hunt_tag_info(attr)
                                    if attr.type in ['md5', 'sha1', 'sha256'] and a_tag:
                                        print(f"    [MATCH] Standalone Attribute {attr.value} tagged '{a_tag}'.")
                                        target_hash = [(attr.value, attr.type)]
                                        process_hashes_and_hunt(misp, hx_token, target_hash, attr.uuid, event_uuid,
                                                                'Attribute', a_tag, a_hours)
                                        action_taken = True

                        if not action_taken:
                            print("    [?] Event loaded but no actionable tags found.")

            last_check_time = current_time

        except Exception as e:
            print(f"[X] Critical Loop Error: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == '__main__':
    main()