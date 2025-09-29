#!/usr/bin/env python3
import requests

api_key = 'api_key'
client_id = 'client_id'
client_token = 'client_token'

total_scopes = "etp.accs.ro etp.accs.rw etp.admn.ro etp.admn.rw etp.alrt.ro etp.alrt.rw etp.conf.ro etp.conf.rw etp.domn.ro etp.domn.rw etp.quar.ro etp.quar.rw etp.rprt.ro etp.rprt.rw etp.trce.ro etp.trce.rw"
allowed_scopes = "etp.accs.ro etp.accs.rw etp.alrt.ro etp.alrt.rw etp.domn.ro etp.quar.ro etp.quar.rw etp.trce.ro etp.trce.rw"
base_url = 'https://us.etp.trellix.com/'


def trellix_api_auth(key=api_key, id=client_id, token=client_token, scopes=allowed_scopes):
    iam_url = "https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token"

    session = requests.Session()

    headers = {
        'x-api-key': key,
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    authx = (id, token)

    payload = {
        'scope': scopes,
        'grant_type': 'client_credentials'
    }

    res = session.post(iam_url, headers=headers, data=payload, auth=authx)

    if res.ok:
        access_token = res.json()['access_token']
        headers['Authorization'] = 'Bearer ' + access_token
        headers['Content-Type'] = 'application/json'
        session.headers.update(headers)
        return session
    else:
        print("Error getting IAM token: {0} - {1}".format(res.status_code, res.text))
        exit()


def open_trellix_session():
    return trellix_api_auth()


def close_trellix_session(session):
    session.close()

def get_alert(session,alert_id):
    filters = {

    }
    alert = session.get(base_url + '/api/v2/public/alerts/' + alert_id, params=filters)
    return alert

def search_alerts(session):
    filters = {
    "date_range":
            {
                "from": "2025-09-02T06:45:01Z",
                "to": "2025-09-29T15:45:01Z"
            },
    }
    alerts = session.post(base_url + '/api/v2/public/alerts/search', json=filters)
    return alerts

session = open_trellix_session()
alert_id = "alert_id"
print(get_alert(session,alert_id).text)
close_trellix_session(session)


