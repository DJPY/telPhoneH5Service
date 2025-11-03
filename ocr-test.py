#!/usr/bin/env
# coding=utf-8

# 国内提高下载速度
# pip install -i https://pypi.tuna.tsinghua.edu.cn/simple 库

import requests
import json

# select data
# mysql=Mysql_crud()
# sql="select * from info where age='24'"
# sql = "select id,name,phone from info"
# info = mysql.mysql_output_data(sql)
# print(info)


url = "https://aip.baidubce.com/oauth/2.0/token?client_id=aAnvV8kxG0X7qHak5h4kVExY&client_secret=3ZFfWiXWcd6vwcn1qlxXjj4XIsGUShpy&grant_type=client_credentials"
payload = ""
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
response = requests.request("POST", url, headers=headers, data=payload)
print(response.text)
