#!/usr/bin/env
#coding=utf-8

#国内提高下载速度
#pip install -i https://pypi.tuna.tsinghua.edu.cn/simple 库

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from typing import Union
from pydantic import BaseModel
from DjSpider.DBcrud import Mysql_crud
from pypinyin import lazy_pinyin, Style
import requests
import json
import jwt


# 启动
# uvicorn main:app --reload  
# uvicorn main:app --host 0.0.0.0 --port 8080 --reload

# # 97-123 小写26个字母  65-91大写26个字母
#     for i in range(65,91):
#         info[chr(i)]=[]


mysql = Mysql_crud()

class ContactItem(BaseModel):
    id:int
    index:str
    name:str
    tel:str
    age:Union[int,str,None]=None
    sex:str
    address:str

class ContactParams(BaseModel):
    id:Union[int,None]=None

class User(BaseModel):
    user:str
    passwd:str

app=FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get('/')
async def home():
    return {'message':"home"}


#login
@app.post('/h5/contact/login')
async def contactLogin(item:User):
    item_dict=item.dict()
    print("item:",item_dict)
    # return {"success":True}
    return item_dict

#联系人列表
@app.post('/h5/contact/list')
async def contactList(item:ContactParams):
    print("item:",item)
    sql = "SELECT * from list ORDER BY `initial`"
    data = mysql.mysql_output_data(sql)
    resp=[]
    info={}    
    return {"data": info,"success":True}


#联系人详情
@app.post('/h5/contact/info')
async def contactInfo(item:ContactParams):
    return {
        item
    }

#baidu OCR
@app.post('/h5/contact/ocr')
async def contactOCR(item:ContactParams):
    url = "https://aip.baidubce.com/oauth/2.0/token?client_id=&client_secret=&grant_type=client_credentials"
    payload = ""
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)
    return {
        item
    }
