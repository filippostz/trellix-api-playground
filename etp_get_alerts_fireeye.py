#!/usr/bin/env python3
import requests

API_KEY = ""

base_url = "https://etp.us.fireeye.com"

headers = {
    "x-fireeye-api-key": API_KEY,
    "Content-Type": "application/json"
}

def get_alert(alert_id):
    filters = {

    }
    alert = requests.get(base_url + '/api/v2/public/alerts/' + alert_id, headers=headers, params=filters)
    return alert

def search_alerts():
    filters = {
    "date_range":
            {
                "from": "2025-09-02T06:45:01Z",
                "to": "2025-10-30T17:45:01Z"
            },
    }
    alerts = requests.post(base_url + '/api/v2/public/alerts/search', headers=headers, json=filters)
    return alerts

def search_traces():
    options = {

            "attributes": {
                "lastModifiedDateTime": {
                    "value": "2025-10-29T09:14:53.276Z",
                    "filter": ">"
                }
            }
        ,

    "size": 300
}
    traces = requests.post(base_url + '/api/v1/messages/trace', headers=headers,json=options)
    return traces

#alert_id = "alert_id"
#print(get_alert(session,alert_id).text)
print(search_alerts().text)
