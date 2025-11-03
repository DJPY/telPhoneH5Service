#!/usr/bin/env
# coding=utf-8

# import random

# code = ''
# for i in range(6):
#     n = random.randint(0, 9)
#     b = chr(random.randint(65, 90))
#     # s = chr(random.randint(97, 122))
#     # print(s)
#     code += str(random.choice([n,b,]))

# print("code:",code)


from DjSpider.DBcrud import Mysql_crud,Redis_crud

# mysql=Mysql_crud()
# sql="SELECT * from list ORDER BY `initial`"
# info = mysql.mysql_output_data(sql)
# print(info)
redis = Redis_crud()
redis.r_set("test@11.com", 111233331)
data = redis.r_get('test@11.com')
print("data:", data)