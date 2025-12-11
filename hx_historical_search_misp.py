import time
import requests
import json
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
HX_BASE_URL = "https://-:3000"
HX_USERNAME = "api_username"
HX_PASSWORD = "api_password"

# --- Polling Config ---
CHECK_INTERVAL = 60  # Seconds between MISP checks
HX_POLL_INTERVAL = 5  # Seconds between HX status checks
HX_MAX_RETRIES = 60  # Max polling attempts for HX search (60*5 = 5 mins)
HX_LOOKBACK_HOURS = 24  # How far back to search in HX history


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
    """Initiates a historical search for a hash (md5/sha256)."""
    search_url = f"{base_url}/hx/api/plugins/historical-search/v1/search"

    # Time window calculation (Timezone Aware)
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
    """Polls for search completion and returns THE LIST OF ITEMS if found."""
    status_url = f"{base_url}/hx/api/plugins/historical-search/v1/status/{search_id}"
    results_url = f"{base_url}/hx/api/plugins/historical-search/v1/results/{search_id}"
    headers = {'X-FeApi-Token': token, 'Accept': 'application/json'}

    print(f"    ... Polling HX Job ID: {search_id}")

    for _ in range(HX_MAX_RETRIES):
        try:
            # Check Status
            res = requests.get(status_url, headers=headers, verify=False)
            res.raise_for_status()
            status = res.json().get('data', {}).get('attributes', {}).get('status')

            if status == 'FINISHED':
                # Fetch Results
                res_data = requests.get(results_url, headers=headers, params={'page[limit]': 10}, verify=False)
                res_data.raise_for_status()
                json_resp = res_data.json()

                # Retrieve specifically the 'items' list.
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


def extract_hashes_from_attributes(attributes):
    """Extracts list of (value, type) from a list of attributes."""
    res = []
    for attr in attributes:
        if attr.type == 'md5':
            res.append((attr.value, 'md5'))
        elif attr.type == 'sha256':
            res.append((attr.value, 'sha256'))
    return res


def has_hunt_tag(item, item_type="Unknown"):
    """
    Robust check for the existence of the hunt tag.
    Handles Case-Insensitivity (hunt == Hunt) and different PyMISP object structures.
    """
    target_tag_lower = TAG_TO_HUNT.lower()

    # Check if item has 'tags' attribute
    if not hasattr(item, 'tags'):
        return False

    # If tags is empty or None
    if not item.tags:
        return False

    # Iterate through tags
    for t in item.tags:
        tag_name = ""

        # Handle MISPTag Object vs Dictionary
        if hasattr(t, 'name'):
            tag_name = t.name
        elif isinstance(t, dict):
            tag_name = t.get('name', '')

        if tag_name.lower() == target_tag_lower:
            return True

    return False


def process_hashes_and_hunt(misp, hx_token, hash_list, entity_uuid, event_uuid, scope_name):
    """
    Iterates through a list of hashes, searches HX, and updates tags.
    entity_uuid: The UUID of the specific thing being tagged (Event, Object, or Attribute).
    event_uuid: The Parent Event UUID (used for adding the text comment).
    scope_name: 'Event', 'Object', or 'Attribute' (for logging).
    """
    # Deduplicate
    hash_list = list(set(hash_list))
    print(f"    -> Scope: {scope_name.upper()} {entity_uuid} | Hashes to check: {len(hash_list)}")

    hit_found = False
    matched_val = None
    matched_type = None

    for val, h_type in hash_list:
        print(f"       Searching {h_type.upper()}: {val}")
        job_id = search_hx_hash(HX_BASE_URL, hx_token, val, h_type)

        if job_id:
            results = wait_and_get_results(HX_BASE_URL, hx_token, job_id)
            if results:
                count = len(results)
                print(f"       [MATCH] Found on {count} host(s)!")
                hit_found = True
                matched_val = val
                matched_type = h_type
                break
            else:
                print(f"       [CLEAN] Not found.")
        else:
            print(f"       [ERROR] Search init failed.")

    if hit_found:
        print(f"    -> Hit found. Updating tags on {scope_name} UUID {entity_uuid}...")
        try:
            # 1. Update Tags on the specific entity (Event, Object, or Attribute)
            misp.untag(entity_uuid, TAG_TO_HUNT)
            misp.tag(entity_uuid, TAG_ON_MATCH)

            # 2. Add Comment to the PARENT EVENT
            comment_text = f"Auto-Hunt: {matched_type.upper()} {matched_val} found in environment (Scope: {scope_name})."

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

    print(f"[*] Listening for events with tag '{TAG_TO_HUNT}'...")

    # We initialize "last check" to now.
    # NOTE: If you want to process OLD tags on restart, comment out the next line
    # and hardcode a past date, e.g., datetime(2023, 1, 1, tzinfo=timezone.utc)
    last_check_time = datetime.now(timezone.utc)

    while True:
        try:
            # 1. Define 'now' at start of cycle
            current_time = datetime.now(timezone.utc)

            # 2. Add a small buffer (e.g., 10 seconds) to ensure we don't miss split-second updates
            # between the last loop finish and this loop start.
            search_timestamp = last_check_time - timedelta(seconds=10)
            timestamp_filter = search_timestamp.strftime('%Y-%m-%d %H:%M:%S')

            # Search returns ANY event that has the tag anywhere
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
                        event_id = event.id
                        event_uuid = event.uuid

                        # NO CACHE CHECK HERE.
                        # We always process found events. If they still have the 'hunt' tag,
                        # it means we haven't successfully processed them yet.

                        print(f"\n[!] Inspecting Event {event_id}: {event.info}")

                        action_taken = False

                        # -----------------------------------------------
                        # PRIORITY 1: IS THE EVENT ITSELF TAGGED?
                        # -----------------------------------------------
                        if has_hunt_tag(event, "Event"):
                            print("    [MATCH] Event-level tag found. Scanning EVERYTHING.")
                            all_hashes = []
                            # Get standalone attributes
                            if hasattr(event, 'attributes'):
                                all_hashes.extend(extract_hashes_from_attributes(event.attributes))
                            # Get attributes inside objects
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
                            # -----------------------------------------------
                            # PRIORITY 2: CHECK OBJECTS & ATTRIBUTES
                            # -----------------------------------------------

                            # A. Check Objects
                            if hasattr(event, 'objects'):
                                for obj in event.objects:
                                    # Is the Object Tagged?
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
                                        # Check attributes inside untagged objects
                                        if hasattr(obj, 'attributes'):
                                            for attr in obj.attributes:
                                                if attr.type in ['md5', 'sha256'] and has_hunt_tag(attr,
                                                                                                   "Attr (In Object)"):
                                                    print(f"    [MATCH] Object Attribute {attr.value} tagged.")
                                                    target_hash = [(attr.value, attr.type)]
                                                    process_hashes_and_hunt(misp, hx_token, target_hash, attr.uuid,
                                                                            event_uuid, 'Attribute')
                                                    action_taken = True

                            # B. Check Standalone Attributes (Attributes not in Objects)
                            if hasattr(event, 'attributes'):
                                for attr in event.attributes:
                                    if attr.type in ['md5', 'sha256'] and has_hunt_tag(attr, "Attr (Standalone)"):
                                        print(f"    [MATCH] Standalone Attribute {attr.value} tagged.")
                                        target_hash = [(attr.value, attr.type)]
                                        process_hashes_and_hunt(misp, hx_token, target_hash, attr.uuid, event_uuid,
                                                                'Attribute')
                                        action_taken = True

                        if not action_taken:
                            print("    [?] Event loaded but no actionable tags found (check spelling/tag location).")

            # Update last check time only after successful loop
            last_check_time = current_time

        except Exception as e:
            print(f"[X] Critical Loop Error: {e}")

        time.sleep(CHECK_INTERVAL)


if __name__ == '__main__':
    main()