import requests
import json
import sys
from requests.auth import HTTPBasicAuth

# --- CONFIGURATION ---
CLIENT_ID = 'YOUR_CLIENT_ID'
CLIENT_SECRET = 'YOUR_CLIENT_SECRET'
API_KEY = 'YOUR_API_KEY'
IAM_URL = 'https://iam.cloud.trellix.com/iam/v1.1/token'
BASE_URL = 'https://api.manage.trellix.com'

# ENDPOINTS
EVENTS_ENDPOINT = '/epo/v2/events'

# SCOPES
SCOPES = 'epo.evt.r'

# PAGINATION SETTING
PAGE_LIMIT = 10


def get_auth_token():
    """
    Authenticates with Trellix IAM using Basic Auth.
    """
    print("Authenticating...")
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'grant_type': 'client_credentials', 'scope': SCOPES}

    try:
        response = requests.post(
            IAM_URL,
            headers=headers,
            data=data,
            auth=HTTPBasicAuth(CLIENT_ID, CLIENT_SECRET)
        )
        if not response.ok:
            print(f"!!! AUTHENTICATION FAILED !!!")
            print(f"Status: {response.status_code}")
            print(f"Message: {response.text}")
            sys.exit(1)
        response.raise_for_status()
        return response.json()['access_token']
    except requests.exceptions.RequestException as e:
        print(f"Connection error: {e}")
        sys.exit(1)


def get_threat_events(token):
    """
    Retrieves the main list of events (limit 10).
    """
    url = f"{BASE_URL}{EVENTS_ENDPOINT}"

    headers = {
        'Authorization': f'Bearer {token}',
        'x-api-key': API_KEY,
        'Content-Type': 'application/vnd.api+json'
    }

    params = {
        'page[limit]': PAGE_LIMIT,
        'sort': '-timestamp'
    }

    print(f"Fetching events (Limit: {PAGE_LIMIT})...")

    try:
        response = requests.get(url, headers=headers, params=params)
        if not response.ok:
            print(f"Failed to fetch list. Status: {response.status_code}")
            sys.exit(1)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        sys.exit(1)


def get_single_event(token, event_id):
    """
    Retrieves details for a single event by ID.
    """
    url = f"{BASE_URL}{EVENTS_ENDPOINT}/{event_id}"
    headers = {
        'Authorization': f'Bearer {token}',
        'x-api-key': API_KEY,
        'Content-Type': 'application/vnd.api+json'
    }
    try:
        response = requests.get(url, headers=headers)
        return response.json() if response.ok else None
    except requests.exceptions.RequestException:
        return None


def main():
    # 1. Get Token & List
    token = get_auth_token()
    response_json = get_threat_events(token)

    # 2. Extract Data and Links (We ignore 'meta' as it's missing)
    events = response_json.get('data', [])
    links = response_json.get('links', {})

    if events:
        print(f"\nSuccessfully retrieved {len(events)} alerts.\n")
        print(f"{'EVENT ID':<40} | {'TYPE':<20} | {'TIMESTAMP'}")
        print("-" * 90)

        for event in events:
            e_id = event.get('id', 'N/A')
            e_type = event.get('type', 'N/A')
            attrs = event.get('attributes', {})
            e_time = attrs.get('timestamp', 'N/A')
            print(f"{e_id:<40} | {e_type:<20} | {e_time}")

        # --- PAGINATION DETAILS (Cursor Based) ---
        print("\n" + "=" * 80)
        print(" PAGINATION STATUS")
        print("=" * 80)

        # Check if a 'next' link exists
        next_link = links.get('next')

        if next_link:
            print("More results are available.")
            print("To fetch the next page, use this API URL found in links['next']:")
            print(f"NEXT LINK: {BASE_URL}{next_link}")
        else:
            print("No 'next' link found. You have reached the end of the results.")

        # --- DEMO: FETCH LAST EVENT DETAILS ---
        print("\n" + "=" * 80)
        print(" DEMO PURPOSE: DETAILS OF THE LAST EVENT")
        print("=" * 80)

        last_event_id = events[-1]['id']
        single_event_details = get_single_event(token, last_event_id)

        if single_event_details:
            print(f"Fetching details for ID: {last_event_id}")
            print(json.dumps(single_event_details, indent=4))
        else:
            print("Could not retrieve details.")

    else:
        print("No events found.")


if __name__ == "__main__":
    main()