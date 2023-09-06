import requests
import json

response = requests.get('https://api.stackexchange.com/2.3/questions?order=desc&sort=activity&site=stackoverflow')
#print(response.json()['items'])
for data in response.json()['items']:
    if data['answer_count']==0:
      print(data['link'])
      print(data['title'])
    else:
       print('skipped')
    print()
    