#!/usr/bin/env python3
import requests
import json
import datetime
import sys

API_KEY = ''
CLIENT_ID = ''
CLIENT_TOKEN = ''

DEFAULT_SCOPES = "soc.act.tg soc.cfg.r soc.cfg.w mi.user.investigate"
BASE_URL = "https://api.manage.trellix.com"
IAM_URL = "https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token"


def get_epoch_utc_millis(past_days: int) -> int:
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    past = now - datetime.timedelta(days=past_days)
    return int(past.timestamp() * 1000)


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


def get_edr_threats(session: requests.Session, days: int) -> dict:
    filters = {
        'from': get_epoch_utc_millis(days),
        'include': 'detections',
        'sort': 'firstDetected'
    }
    api_url = f"{BASE_URL}/edr/v2/threats"

    try:
        response = session.get(api_url, params=filters)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        raise Exception(f"Error fetching EDR threats: {e}") from e


def main():
    days_to_query = 10

    try:
        with create_trellix_session(
                API_KEY, CLIENT_ID, CLIENT_TOKEN, DEFAULT_SCOPES
        ) as session:
            threats = get_edr_threats(session, days_to_query)
            print(json.dumps(threats, indent=2))
    except Exception as e:
        print(f"An error occurred: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()