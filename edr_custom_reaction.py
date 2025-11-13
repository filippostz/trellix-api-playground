#!/usr/bin/env python3
import sys
import requests
import time
from typing import Optional

API_KEY = ''
CLIENT_ID = ''
CLIENT_TOKEN = ''

DEFAULT_SCOPES = "soc.act.tg soc.cfg.r soc.cfg.w mi.user.investigate"
BASE_URL = "https://api.manage.trellix.com"
IAM_URL = "https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token"


def create_trellix_session(
        key: str, client_id: str, token: str, scopes: str
) -> requests.Session:
    if not all([key, client_id, token]):
        print(
            "Error: TRELLIX_API_KEY, TRELLIX_CLIENT_ID, and TRELLIX_CLIENT_TOKEN "
            "must be set",
            file=sys.stderr
        )
        sys.exit(1)

    session = requests.Session()
    headers = {
        'x-api-key': key,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    auth = (client_id, token)
    payload = {
        'scope': scopes,
        'grant_type': 'client_credentials'
    }

    try:
        res = session.post(IAM_URL, headers=headers, data=payload, auth=auth)
        res.raise_for_status()
        access_token = res.json()['access_token']

        session.headers.update({
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/vnd.api+json',
            'x-api-key': key
        })
        return session
    except (requests.exceptions.RequestException, KeyError) as e:
        session.close()
        raise Exception(f"Error during authentication: {e}") from e


def custom_reaction_host(session: requests.Session, action, hostname: str):
    """
    Finds a host by hostname, waits for the search, and triggers an action
    reaction for all results.
    """

    # --- Configuration ---
    search_api_url = "https://api.soc.trellix.com/active-response/api/v1/searches"
    remediation_api_url = "https://api.soc.trellix.com/remediation/api/v1/actions/search-results-actions"
    poll_interval_seconds = 10
    max_poll_attempts = 30  # 5 minute timeout (30 attempts * 10 seconds)

    # --- 1. Start Search ---
    search_payload = {
        "projections": [{"name": "HostInfo"}],
        "condition": {"or": [{"and": [{"name": "HostInfo", "output": "hostname", "op": "EQUALS", "value": hostname}]}]}
    }

    query_id: Optional[str] = None
    try:
        print(f"Starting search for hostname: {hostname}...")
        search_response = session.post(search_api_url, json=search_payload)
        search_response.raise_for_status()

        response_data = search_response.json()
        query_id = response_data.get('id')

        if not query_id:
            print(f"Error: API response for search start missing 'id'. Response: {response_data}")
            return

        print(f"Search started with query ID: {query_id}")

    except requests.exceptions.RequestException as e:
        print(f"Error: API request failed while starting search: {e}")
        return
    except Exception as e:
        print(f"An unexpected error occurred during search start: {e}")
        return

    # --- 2. Poll for Status ---
    status_url = f"{search_api_url}/{query_id}/status"
    status_query = False

    print("Waiting for search results...")
    for attempt in range(max_poll_attempts):
        try:
            time.sleep(poll_interval_seconds)
            status_res = session.get(status_url)
            status_res.raise_for_status()

            status = status_res.json().get('status')
            if status == 'FINISHED':
                status_query = True
                print('\nSearch FINISHED.')
                time.sleep(2)
                break
            else:
                print(f"\rWaiting for search... Status: {status} (Attempt {attempt + 1}/{max_poll_attempts})", end="")

        except requests.exceptions.RequestException as e:
            print(f"\nError: API request failed while polling status: {e}")
            # Allow loop to retry if attempts remain

    if not status_query:
        print(f"\nError: Search {query_id} timed out after {max_poll_attempts} attempts.")
        return

    # --- 3. Get Results ---
    results_url = f"{search_api_url}/{query_id}/results"
    try:
        search_results_res = session.get(results_url)
        search_results_res.raise_for_status()

        items = search_results_res.json().get('items')
        if not items:
            print("Search complete. No results found.")
            return

        print(f"Found {len(items)} results. Triggering the action...")

        # --- 4. Trigger Action for each Result ---
        for item in items:
            result_id = item.get('id')
            if not result_id:
                print(f"Warning: Found a result item with no 'id'. Skipping. Item: {item}")
                continue

            action_payload = {
                "action": action,
                "searchResultsArguments": {"searchId": query_id, "rowsIds": [result_id], "arguments": {}},
                "provider": "AR"
            }

            try:
                action_res = session.post(remediation_api_url, json=action_payload)
                action_res.raise_for_status()
                print(f"Action successfully triggered for result_id: {result_id}")
            except requests.exceptions.RequestException as e:
                print(f"Error: API request failed while triggering the action for result {result_id}: {e}")
                # Continue to the next item

    except requests.exceptions.RequestException as e:
        print(f"\nError: API request failed while getting results: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during results processing: {e}")

def main():

    try:
        with create_trellix_session(
                API_KEY, CLIENT_ID, CLIENT_TOKEN, DEFAULT_SCOPES
        ) as session:
            #custom_reaction_host(session, custom_action_name, hostname)
            custom_reaction_host(session, "_Ping", "TAP01")

    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":

    main()
