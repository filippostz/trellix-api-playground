import requests

API='your key here'

def push_event(headers,data):
    response = requests.post('https://helix-integrations.cloud.aws.apps.fireeye.com/api/upload', headers=headers,data=data)
    if response.ok:
        print('Success!')
    else:
        print('Error!')

def push_log(event):
    headers = {'Authorization': f'{API}', }
    push_event(headers,event)

push_log('{"metaclass":"cloud","class":"test123","service":"test","status":"enable"}')
