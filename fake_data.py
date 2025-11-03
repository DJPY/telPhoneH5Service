#!/usr/bin/env
# coding=utf-8

from faker import Faker
import datetime
from pypinyin import lazy_pinyin, Style

faker = Faker(["zh_CN"])
Faker.seed(0)

def get_data():
    # key_list=["姓名","年龄","生日","电话","地址","邮箱","创建时间","首写字母"]
    key_list=["name","age","birthday","phone","address","email","create_time","initial"]
    name=faker.name()
    # age=faker.random_int(18,29)
    # birthday=faker.ssn()[6:14]
    birthday = faker.date_between(start_date="-28y",end_date="-18y")
    year = datetime.date.today().year
    age = year-birthday.year
    phone = faker.phone_number()
    address = faker.address()
    email=faker.email()
    create_time = faker.date_time_between(start_date="-1y",end_date="now")
    initial = lazy_pinyin(name, style=Style.FIRST_LETTER)[0].upper()
    info_list=[name,age,birthday,phone,address,email,create_time,initial]
    person_info=dict(zip(key_list,info_list))
    return person_info

# data = get_data()
# print(data)
