import jwt, datetime, time
from flask import jsonify
from app.users.model import Users
from .. import config
from .. import common
from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()
 
 
class Auth():
    @staticmethod
    def encode_auth_token(user_id):
        # 申请Token,参数为自定义,user_id不必须,此处为以后认证作准备,程序员可以根据情况自定义不同参数
        """
        生成认证Token
        :param user_id: int
        :param login_time: int(timestamp)
        :return: string
        """
        try:
 
            headers = {
                "typ": "JWT",
                "alg": "HS256",
                "user_id": user_id
            }
 
            playload = {
                "headers": headers,
                "iss": 'ly',
                "exp": datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=0, minutes=1, seconds=0),
                'iat': datetime.datetime.utcnow()
            }
 
            signature = jwt.encode(playload, config.SECRET_KEY, algorithm='HS256')
            return signature
 
        except Exception as e:
            return e
 
        # encode为加密函数，decode为解密函数(HS256)
 
        # JWT官网的三个加密参数为
        # 1.header(type,algorithm)
        #  {
        #  "alg": "HS256",
        #  "typ": "JWT"
        #  }
        # 2.playload(iss,sub,aud,exp,nbf,lat,jti)
        #   iss: jwt签发者
        #   sub: jwt所面向的用户
        #   aud: 接收jwt的一方
        #   exp: jwt的过期时间，这个过期时间必须要大于签发时间
        #   nbf: 定义在什么时间之前，该jwt都是不可用的.
        #   iat: jwt的签发时间
        #   jti: jwt的唯一身份标识，主要用来作为一次性token,从而回避重放攻击。
        # 3.signature
        #
        # jwt的第三部分是一个签证信息，这个签证信息由三部分组成：
        #
        #    header (base64后的)
        #    payload (base64后的)
        #    secret
 
        # PyJwt官网的三个加密参数为
        # jwt.encode(playload, key, algorithm='HS256')
        # playload 同上,key为app的 SECRET_KEY algorithm 为加密算法
 
        # 二者应该都可以用，但我们用的是python的 pyjwt ，那就入乡随俗吧
 
 
    @staticmethod
    def decode_auth_token(auth_token):
        """
        验证Token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, config.SECRET_KEY, options={'verify_exp': False})
            if payload:
                return payload
            else:
                raise jwt.InvalidTokenError
 
        except jwt.ExpiredSignatureError:
            return 'Token过期'
 
        except jwt.InvalidTokenError:
            return '无效Token'
 
    def authenticate(self, username, password):
        """
        用户登录，登录成功返回token，写将登录时间写入数据库；登录失败返回失败原因
        :param password:
        :return: json
        """
        info = Users.query.filter(username == Users.username).first()
        if info is None:
            return jsonify(common.falseReturn('', '找不到用户'))
        else:
            if info.password == password:
                login_time = int(time.time())
                info.login_time = login_time
                db.session.commit()
                token = self.encode_auth_token(info.id)
                return jsonify(common.trueReturn(token.decode(), '登录成功'))
                # return jsonify(common.trueReturn(jwt.decode(token, config.SECRET_KEY, algorithms='HS256'), '登录成功'))
            else:
                return jsonify(common.falseReturn('', '密码不正确'))
 
    def identify(self, request):
        """
        用户鉴权
        :return: list
        """
        try:
            auth_token = jwt.decode(request.headers.get('Authorization'), config.SECRET_KEY, algorithms='HS256')
            if auth_token:
 
                if not auth_token or auth_token['headers']['typ'] != 'JWT':
                    result = common.falseReturn('', '请传递正确的验证头信息')
                else:
                    user = Users.query.filter(Users.id == auth_token['headers']['user_id']).first()
                    if user is None:
                        result = common.falseReturn('', '找不到该用户信息')
                    else:
                        result = common.trueReturn(user.id, '请求成功')
 
                return result
 
        except jwt.ExpiredSignatureError:
            result = common.falseReturn('Time_Out', 'Token已过期')
            return result
 
        except jwt.InvalidTokenError:
            result = common.falseReturn('Time_Out', '未提供认证Token')
            return result
 