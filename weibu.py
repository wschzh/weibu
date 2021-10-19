import requests
import json

ip = input("要查询的ip：")

url = "https://api.threatbook.cn/v3/scene/ip_reputation"

query = {
    "apikey": "8200f07b178b4b618f802c92274b41ea5d1402cb1d6249fe9806b85bd45fe658",
    "resource": ip,
    "lang": 'zh'
}

response = requests.request("GET", url, params=query)

DATA = response.json()
json_str = json.dumps(DATA)
usr_dict = json.loads(json_str)

location_list = usr_dict['data'][ip]['basic']['location'].values()
print("归属：", usr_dict['data'][ip]['basic']['carrier'], usr_dict['data'][ip]['scene'], list(location_list)[0:3])
if usr_dict['data'][ip]['is_malicious']:
    print("威胁等级：", usr_dict['data'][ip]['severity'])
    print("威胁类型：", usr_dict['data'][ip]['judgments'])
    if usr_dict['data'][ip]['tags_classes']:
        tag_list = []
        for i in usr_dict['data'][ip]['tags_classes']:
            tag_list.append(i['tags'])
        print("标签:", tag_list)
    print("最后更新时间：", usr_dict['data'][ip]['update_time'])
else:
    print("无威胁")
