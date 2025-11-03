#!/usr/bin/env
# coding=utf-8

# 国内提高下载速度
# pip install -i https://pypi.tuna.tsinghua.edu.cn/simple 库

from DjSpider.DBcrud import Mysql_crud
from fake_data import get_data

import requests
import json

# select data
# mysql=Mysql_crud()
# sql="select * from info where age='24'"
# sql = "select id,name,phone from info"
# info = mysql.mysql_output_data(sql)
# print(info)

# insert to mysql data
mysql=Mysql_crud()
for i in range(100):
    info = get_data()
    print(info)
    mysql.mysql_insert_data('list',info)

