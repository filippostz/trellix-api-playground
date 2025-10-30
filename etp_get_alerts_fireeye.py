import requests
import datetime

API_KEY = ""
BASE_URL = "https://etp.us.fireeye.com"
API_ENDPOINT = f"{BASE_URL}/api/v2/public/alerts/search"

def get_etp_alerts():
    """
    Fetches alerts from the FireEye ETP API from the last 24 hours.
    """

    # Set the headers with your API key
    headers = {
        "x-fireeye-api-key": API_KEY,
        "Content-Type": "application/json"
    }

    time_24_hours_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)

    filters = {
    "date_range":
            {
                "from": "2025-10-02T06:45:01Z",
                "to": "2025-10-30T16:45:01Z"
            },
    }

    try:
        response = requests.post(API_ENDPOINT, headers=headers, json=filters)

        if response.status_code == 200:
            alerts_data = response.json()
            print(alerts_data)
            alerts_list = alerts_data.get('data', [])
            print(alerts_list)

    except requests.exceptions.RequestException as e:
        print(f"A connection error occurred: {e}")

if __name__ == "__main__":
    if API_KEY == "":
        print("Error: Please update the 'API_KEY' variable in the script.")
    else:
        get_etp_alerts()
