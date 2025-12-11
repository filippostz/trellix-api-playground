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
TAG_TO_HUNT = 'hunt'
TAG_ON_MATCH = 'prevalent'

# --- Trellix HX Config ---
HX_BASE_URL = "https://----:3000"
HX_USERNAME = "api_username"
HX_PASSWORD = "api_password"

# --- Polling Config ---
CHECK_INTERVAL = 60  # Seconds between MISP checks
HX_POLL_INTERVAL = 5  # Seconds between HX status checks
HX_MAX_RETRIES = 60  # Max polling attempts for HX search (60*5 = 5 mins)
HX_LOOKBACK_HOURS = 24  # How far back to search in HX history
CACHE_TTL_SECONDS = 300  # Prevent reprocessing same event for 5 mins


# ==========================================
#          TRELLIX HX FUNCTIONS
# ==========================================

def get_hx_token(base_url, username, password):
    """Authenticates to HX and returns a session token."""
    token_url = f"{base_url}/hx/api/v3/token"
    try:
        response = requests.head(token_url, auth=(username, password), verify=False)
        response.raise_for_status()
        token = response.headers.get('X-FeApi-Token')
        if token:
            return token
        else:
            print("[X] HX Auth Error: No token in header.")
            return None
    except Exception as e:
        print(f"[X] HX Auth failed: {e}")
        return None


def search_hx_hash(base_url, token, file_hash, hash_type):
    """Initiates a historical search for a hash."""
    search_url = f"{base_url}/hx/api/plugins/historical-search/v1/search"

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=HX_LOOKBACK_HOURS)
    fmt = "%Y-%m-%dT%H:%M:%S.%f"
    t_end = end_time.strftime(fmt)[:-3] + "Z"
    t_start = start_time.strftime(fmt)[:-3] + "Z"

    hx_field = f"fileAttributes.{hash_type}"

    payload = {
        "data": {
            "type": "search",
            "attributes": {
                "query": {
                    "condition": f'{hx_field}="{file_hash}"',
                    "startTime": t_start,
                    "endTime": t_end
                }
            }
        }
    }
    headers = {'X-FeApi-Token': token, 'Content-Type': 'application/json'}

    try:
        res = requests.post(search_url, headers=headers, json=payload, verify=False, params={'maxResults': 100})
        res.raise_for_status()
        return res.json().get('data', {}).get('id')
    except Exception as e:
        print(f"[X] HX Search init failed for {hash_type} {file_hash}: {e}")
        return None


def wait_and_get_results(base_url, token, search_id):
    """Polls for search completion."""
    status_url = f"{base_url}/hx/api/plugins/historical-search/v1/status/{search_id}"
    results_url = f"{base_url}/hx/api/plugins/historical-search/v1/results/{search_id}"
    headers = {'X-FeApi-Token': token, 'Accept': 'application/json'}

    print(f"    ... Polling HX Job ID: {search_id}")

    for _ in range(HX_MAX_RETRIES):
        try:
            res = requests.get(status_url, headers=headers, verify=False)
            res.raise_for_status()
            status = res.json().get('data', {}).get('attributes', {}).get('status')

            if status == 'FINISHED':
                res_data = requests.get(results_url, headers=headers, params={'page[limit]': 50}, verify=False)
                res_data.raise_for_status()
                json_resp = res_data.json()
                items = json_resp.get('data', {}).get('attributes', {}).get('items', [])
                return items

            elif status in ['FAILED', 'STOPPED', 'EXPIRED']:
                print(f"    [!] HX Search stopped with status: {status}")
                return []

            time.sleep(HX_POLL_INTERVAL)
        except Exception as e:
            print(f"    [!] Error polling HX: {e}")
            return []

    print("    [!] HX Search Timed Out.")
    return []


# ==========================================
#          HELPER FUNCTIONS
# ==========================================

def init_misp():
    return PyMISP(MISP_URL, MISP_KEY, ssl=MISP_VERIFY_CERT, debug=False)


def verify_tags_exist(misp):
    """Checks if the required tags exist on the MISP instance."""
    print("[*] Verifying required tags on MISP...")
    missing_tags = []

    for tag_name in [TAG_TO_HUNT, TAG_ON_MATCH]:
        tag_found = False
        try:
            res = misp.search_tags(tag_name, pythonify=True)
            if res:
                for t in res:
                    found_name = t.name if hasattr(t, 'name') else t.get('name', '')
                    if found_name.lower() == tag_name.lower():
                        tag_found = True
                        break
            if not tag_found:
                missing_tags.append(tag_name)
        except Exception as e:
            print(f"[X] Error checking tag '{tag_name}': {e}")
            missing_tags.append(tag_name)

    if missing_tags:
        print(f"[!] CRITICAL: Missing tags in MISP: {missing_tags}")
        return False

    print("    -> All required tags found.")
    return True


def extract_hashes_from_attributes(attributes):
    res = []
    for attr in attributes:
        if attr.type == 'md5':
            res.append((attr.value, 'md5'))
        elif attr.type == 'sha1':
            res.append((attr.value, 'sha1'))
        elif attr.type == 'sha256':
            res.append((attr.value, 'sha256'))
    return res


def has_hunt_tag(item, item_type="Unknown"):
    target_tag_lower = TAG_TO_HUNT.lower()
    if not hasattr(item, 'tags') or not item.tags:
        return False

    for t in item.tags:
        tag_name = ""
        if hasattr(t, 'name'):
            tag_name = t.name
        elif isinstance(t, dict):
            tag_name = t.get('name', '')

        if tag_name.lower() == target_tag_lower:
            return True
    return False


def process_hashes_and_hunt(misp, hx_token, hash_list, entity_uuid, event_uuid, scope_name):
    """
    Iterates through hashes, searches HX, collects ALL hits, and THEN updates tags/comments.
    """
    hash_list = list(set(hash_list))
    print(f"    -> Scope: {scope_name.upper()} {entity_uuid} | Hashes to check: {len(hash_list)}")

    found_hits = []  # Store all findings here

    for val, h_type in hash_list:
        print(f"       Searching {h_type.upper()}: {val}")
        job_id = search_hx_hash(HX_BASE_URL, hx_token, val, h_type)

        if job_id:
            results = wait_and_get_results(HX_BASE_URL, hx_token, job_id)
            if results:
                count = len(results)
                print(f"       [MATCH] Found on {count} hit(s)!")

                # Extract hosts
                current_hosts = set()
                for item in results:
                    h = item.get('output', {}).get('host')
                    if h: current_hosts.add(h)

                # Add to findings
                found_hits.append({
                    'type': h_type,
                    'val': val,
                    'count': count,
                    'hosts': sorted(list(current_hosts))
                })
            else:
                print(f"       [CLEAN] Not found.")
        else:
            print(f"       [ERROR] Search init failed.")

    # Check if ANY matches were found after scanning ALL hashes
    if found_hits:
        print(f"    -> {len(found_hits)} IOC(s) confirmed found. Updating tags and comment...")

        try:
            misp.untag(entity_uuid, TAG_TO_HUNT)
            misp.tag(entity_uuid, TAG_ON_MATCH)

            # Build Aggregate Comment
            # Example: "Auto-Hunt: Found 2 IOCs. 1) MD5 abc on Host1. 2) SHA1 xyz on Host2, Host3."
            summary_lines = []
            for hit in found_hits:
                # Host string formatting (limit length)
                hosts_str = ", ".join(hit['hosts'][:10])
                if len(hit['hosts']) > 10:
                    hosts_str += f" (+{len(hit['hosts']) - 10} others)"
                elif not hit['hosts']:
                    hosts_str = "Unknown Host"

                summary_lines.append(f"{hit['type'].upper()} {hit['val']} on {hosts_str}")

            comment_body = "; ".join(summary_lines)
            comment_text = f"Auto-Hunt (Scope: {scope_name}): Found {len(found_hits)} IOCs. {comment_body}"

            # Safety truncate if massive
            if len(comment_text) > 65000:
                comment_text = comment_text[:65000] + "...(truncated)"

            attribute_data = {
                'type': 'text',
                'value': comment_text,
                'category': 'Internal reference',
                'to_ids': False,
                'comment': 'Added by Auto-Hunt Script'
            }
            misp.add_attribute(event_uuid, attribute_data)

            print("    -> Tags and comment updated.")
            return True
        except Exception as e:
            print(f"    [X] Error updating tags: {e}")
            return False

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

    print(f"[*] Listening for events with tag '{TAG_TO_HUNT}'...")

    processed_events_ttl = {}
    last_check_time = datetime.now(timezone.utc)

    while True:
        try:
            current_time = datetime.now(timezone.utc)

            # Cleanup cache
            keys_to_remove = [k for k, v in processed_events_ttl.items() if
                              (current_time - v).total_seconds() > CACHE_TTL_SECONDS]
            for k in keys_to_remove:
                del processed_events_ttl[k]

            search_timestamp = last_check_time - timedelta(seconds=10)
            timestamp_filter = search_timestamp.strftime('%Y-%m-%d %H:%M:%S')

            response = misp.search(
                tags=[TAG_TO_HUNT],
                timestamp=timestamp_filter,
                pythonify=True
            )

            if response:
                hx_token = get_hx_token(HX_BASE_URL, HX_USERNAME, HX_PASSWORD)

                if not hx_token:
                    print("[!] HX Auth failed. Skipping batch.")
                else:
                    for event in response:
                        event_id_str = str(event.id)
                        event_uuid = event.uuid

                        # Cache Check
                        if event_id_str in processed_events_ttl:
                            continue

                        processed_events_ttl[event_id_str] = current_time

                        print(f"\n[!] Inspecting Event {event_id_str}: {event.info}")

                        action_taken = False

                        # 1. Event Level Check
                        if has_hunt_tag(event, "Event"):
                            print("    [MATCH] Event-level tag found. Scanning EVERYTHING.")
                            all_hashes = []
                            if hasattr(event, 'attributes'):
                                all_hashes.extend(extract_hashes_from_attributes(event.attributes))
                            if hasattr(event, 'objects'):
                                for obj in event.objects:
                                    if hasattr(obj, 'attributes'):
                                        all_hashes.extend(extract_hashes_from_attributes(obj.attributes))

                            if all_hashes:
                                process_hashes_and_hunt(misp, hx_token, all_hashes, event_uuid, event_uuid, 'Event')
                                action_taken = True
                            else:
                                print("    [!] No hashes found in this event.")

                        else:
                            # 2. Object & Attribute Level Checks
                            if hasattr(event, 'objects'):
                                for obj in event.objects:
                                    if has_hunt_tag(obj, "Object"):
                                        print(f"    [MATCH] Object {obj.name} ({obj.uuid}) tagged.")
                                        obj_hashes = []
                                        if hasattr(obj, 'attributes'):
                                            obj_hashes.extend(extract_hashes_from_attributes(obj.attributes))

                                        if obj_hashes:
                                            process_hashes_and_hunt(misp, hx_token, obj_hashes, obj.uuid, event_uuid,
                                                                    'Object')
                                            action_taken = True
                                        else:
                                            print(f"    [!] Tagged object {obj.name} has no hashes.")
                                    else:
                                        if hasattr(obj, 'attributes'):
                                            for attr in obj.attributes:
                                                if attr.type in ['md5', 'sha1', 'sha256'] and has_hunt_tag(attr,
                                                                                                           "Attr (In Object)"):
                                                    print(f"    [MATCH] Object Attribute {attr.value} tagged.")
                                                    target_hash = [(attr.value, attr.type)]
                                                    process_hashes_and_hunt(misp, hx_token, target_hash, attr.uuid,
                                                                            event_uuid, 'Attribute')
                                                    action_taken = True

                            if hasattr(event, 'attributes'):
                                for attr in event.attributes:
                                    if attr.type in ['md5', 'sha1', 'sha256'] and has_hunt_tag(attr,
                                                                                               "Attr (Standalone)"):
                                        print(f"    [MATCH] Standalone Attribute {attr.value} tagged.")
                                        target_hash = [(attr.value, attr.type)]
                                        process_hashes_and_hunt(misp, hx_token, target_hash, attr.uuid, event_uuid,
                                                                'Attribute')
                                        action_taken = True

                        if not action_taken:
                            print("    [?] Event loaded but no actionable tags found.")

            last_check_time = current_time

        except Exception as e:
            print(f"[X] Critical Loop Error: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == '__main__':
    main()