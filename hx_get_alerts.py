import requests
import json
from urllib3.exceptions import InsecureRequestWarning

# Suppress the insecure request warning caused by verify=False
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# --- User Configuration ---
# TODO: Replace the placeholder values below with your actual information
USERNAME = "api_username"
PASSWORD = "api_password"
BASE_URL = f'https://___.apps.xdr.trellix.com'


def get_auth_token(base_url, username, password):
    print("Step 1: Attempting to get authentication token...")
    token_url = f"{base_url}/hx/api/v3/token"
    auth_credentials = (username, password)

    try:
        response = requests.head(
            token_url,
            auth=auth_credentials,
            verify=False
        )
        response.raise_for_status()
        token = response.headers.get('X-FeApi-Token')
        if token:
            print("Token acquired successfully!")
            return token
        else:
            print("Error: 'X-FeApi-Token' not found in response.")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Error during authentication: {e}")
        return None


def get_hx_alerts(base_url, token):
    print("\nStep 2: Fetching alerts with the token...")
    alerts_url = f"{base_url}/hx/api/v3/alerts"
    headers = {
        'X-FeApi-Token': token,
        'Accept': 'application/json'
    }

    try:
        response = requests.get(
            alerts_url,
            headers=headers,
            verify=False
        )
        response.raise_for_status()
        print("Alerts fetched successfully!")
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching alerts: {e}")
        return None
    except json.JSONDecodeError:
        print("Error: Failed to decode JSON from response.")
        return None


# --- Main Execution ---
if __name__ == "__main__":
    auth_token = get_auth_token(BASE_URL, USERNAME, PASSWORD)

    # If the token was successfully retrieved, use it to get alerts
    if auth_token:
        alert_data = get_hx_alerts(BASE_URL, auth_token)

        if alert_data:
            alerts_list = alert_data.get('data', {}).get('entries', [])

            print(f"\n--- Results ---")
            print(f"Found {len(alerts_list)} alerts.")

            for i, alert in enumerate(alerts_list[:3]):
                print(f"\n--- Alert #{i + 1} ---")
                print(json.dumps(alert, indent=2))

            if not alerts_list:
                print("The response contained no alert entries.")
