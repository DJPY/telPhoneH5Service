#!/usr/bin/env
# coding=utf-8

import random
import smtplib
import time
from email.mime.text import MIMEText


class contact():
    def __init__(self):
        print("contact run")

    # 生成6位验证码
    def getCode(self):
        code = ''
        for i in range(6):
            n = random.randint(0, 9)
            b = chr(random.randint(65, 90))
            # s = chr(random.randint(97, 122))
            # print(s)
            code += str(random.choice([n, b,]))
        return code
    
    # 生成用户id
    def getUserId(self):
        time = time.time()
        userId = int(round(time*1000))
        print("userId:",userId)
        return userId

    #  发送邮件
    def postMail(self,mail,conten):
        mail_host = 'smtp.163.com'
        mail_user = 'dingjiangping2023'
        mail_pass = 'STCJDJRVFEYDTUDE'
        sender = 'dingjiangping2023@163.com'
        receivers = [mail]
        message = MIMEText('content', 'plain', 'utf-8')
        message['Subject'] = conten
        message['From'] = sender
        message['To'] = receivers[0]
        # 登录并发送邮件
        try:
            smtpObj = smtplib.SMTP()
            # 连接到服务器
            smtpObj.connect(mail_host, 25)
            # 登录到服务器
            smtpObj.login(mail_user, mail_pass)
            # 发送
            smtpObj.sendmail(
                sender, receivers, message.as_string())
            # 退出
            smtpObj.quit()
            print('success')
            return True
        except smtplib.SMTPException as e:
            print('error', e)  # 打印错误
            return False

if __name__ == "__main__":
    print('okfunc')