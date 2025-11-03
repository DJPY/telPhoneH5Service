#!/usr/bin/env
#coding=utf-8

from fastapi import FastAPI, HTTPException, Depends, Header, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import Union, Optional, Dict, Any
from pydantic import BaseModel, field_validator
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import jwt
import datetime
import time
import re
import logging
import requests

# 导入配置和工具
from config import config
from DjSpider.DBcrud import Mysql_crud, Redis_crud
from contactFuc import contact

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# JWT 常量配置（从 config 导入）
SECRET_KEY = config.SECRET_KEY
JWT_ALGORITHM = config.JWT_ALGORITHM
JWT_EXPIRE_MINUTES = config.JWT_EXPIRE_MINUTES

# 密码加密上下文（使用 bcrypt）
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 请求限流器
limiter = Limiter(key_func=get_remote_address)

# 数据库连接
try:
    mysql = Mysql_crud(
        host=config.DB_CONFIG['host'],
        port=config.DB_CONFIG['port'],
        user=config.DB_CONFIG['user'],
        passwd=config.DB_CONFIG['password'],
        db=config.DB_CONFIG['database'],
        charset=config.DB_CONFIG['charset']
    )
    logger.info("MySQL 连接成功")
except Exception as e:
    logger.error(f"MySQL 连接失败: {str(e)}")
    raise

try:
    redis = Redis_crud(
        host=config.REDIS_CONFIG['host'],
        port=config.REDIS_CONFIG['port'],
        db=config.REDIS_CONFIG['db'],
        password=config.REDIS_CONFIG['password']
    )
    logger.info("Redis 连接成功")
except Exception as e:
    logger.error(f"Redis 连接失败: {str(e)}")
    raise

contact = contact()

# ==================== Pydantic 模型定义 ====================

class ContactItem(BaseModel):
    """联系人信息模型"""
    id: int
    index: str
    name: str
    tel: str
    age: Union[int, str, None] = None
    sex: str
    address: str

    @field_validator('tel')
    @classmethod
    def validate_tel(cls, v):
        if not re.match(r'^1[3-9]\d{9}$', v):
            raise ValueError('请输入有效的中国手机号码')
        return v


class ContactParams(BaseModel):
    """联系人查询参数"""
    id: Union[int, None] = None


class User(BaseModel):
    """用户登录模型"""
    user: str
    passwd: str


class Code(BaseModel):
    """验证码请求模型"""
    email: str

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('请输入有效的邮箱地址')
        return v


class Sign(BaseModel):
    """用户注册模型"""
    user: str
    passwd: str
    email: str
    code: Union[str, None] = None

    @field_validator('user')
    @classmethod
    def validate_user(cls, v):
        if not re.match(r'^[a-zA-Z0-9_]{3,20}$', v):
            raise ValueError('用户名必须是3-20位的字母、数字或下划线')
        return v

    @field_validator('passwd')
    @classmethod
    def validate_passwd(cls, v):
        if len(v) < 6:
            raise ValueError('密码长度不能少于6位')
        return v

    @field_validator('email')
    @classmethod
    def validate_email(cls, v):
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', v):
            raise ValueError('请输入有效的邮箱地址')
        return v


# ==================== 安全函数 ====================

def hash_password(password: str) -> str:
    """
    使用 bcrypt 加密密码
    :param password: 明文密码
    :return: 加密后的密码
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    验证密码
    :param plain_password: 明文密码
    :param hashed_password: 加密后的密码
    :return: 是否匹配
    """
    return pwd_context.verify(plain_password, hashed_password)


def encode_auth_token(user_id: int, username: str) -> str:
    """
    生成 JWT Token
    :param user_id: 用户ID
    :param username: 用户名
    :return: JWT Token字符串
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRE_MINUTES),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id,
            'username': username
        }
        return jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
    except Exception as e:
        logger.error(f"Token生成失败: {str(e)}")
        raise HTTPException(status_code=500, detail="Token生成失败")


def decode_auth_token(auth_token: str) -> dict:
    """
    验证 JWT Token
    :param auth_token: JWT Token
    :return: 解码后的 payload
    """
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token已过期")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="无效的Token")


async def verify_token(authorization: Optional[str] = Header(None)) -> dict:
    """
    验证 Token 的依赖函数
    :param authorization: Authorization 头
    :return: 用户信息字典
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="未提供认证信息")

    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=401, detail="认证方案无效")

        payload = decode_auth_token(token)

        # 验证用户是否仍然存在
        sql = "SELECT * FROM user WHERE id = %s AND username = %s"
        users = mysql.mysql_output_data(sql, (payload['sub'], payload['username']))
        if not users:
            raise HTTPException(status_code=401, detail="用户不存在或已被删除")

        return {"user": users[0], "payload": payload}
    except ValueError:
        raise HTTPException(status_code=401, detail="认证信息格式错误")


# ==================== FastAPI 应用初始化 ====================

app = FastAPI(
    title="通讯录H5",
    description="联系人管理系统API",
    version="2.0.0"
)

# 添加请求限流
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS 中间件配置（使用配置文件中的设置）
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS if config.CORS_ORIGINS != ["*"] else ["http://localhost:3000", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

# ==================== 全局异常处理 ====================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """处理 HTTP 异常"""
    logger.warning(f"HTTP异常: {exc.status_code} - {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": exc.status_code, "message": exc.detail, "data": None}
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """处理通用异常"""
    logger.error(f"服务器错误: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"code": 500, "message": "服务器内部错误", "data": None}
    )


# ==================== API 路由 ====================

@app.get('/')
@limiter.limit("10/minute")
async def home(request: Request):
    """首页接口"""
    return {'message': "联系人管理系统 API v2.0", 'status': 'running'}


@app.post('/h5/contact/code')
@limiter.limit("3/minute")
async def contactCode(request: Request, item: Code):
    """
    发送邮箱验证码
    限流: 每分钟最多3次
    """
    item_dict = item.dict()
    logger.info(f"请求验证码: {item_dict['email']}")

    try:
        # 生成6位验证码
        code = contact.getCode()
        content = f"您的验证码为：{code}，有效期5分钟"

        # 将验证码存入 Redis，设置5分钟过期
        redis.redis_conn.setex(f"email_code:{item_dict['email']}", 300, code)

        # 发送邮件（如果配置了邮件服务）
        # contact.postMail(item_dict['email'], content)

        logger.info(f"验证码已生成: {item_dict['email']}")
        return {"success": True, "message": "验证码已发送"}
    except Exception as e:
        logger.error(f"发送验证码失败: {str(e)}")
        raise HTTPException(status_code=500, detail="验证码发送失败")


@app.post('/h5/contact/sign')
@limiter.limit("5/minute")
async def contactSign(request: Request, item: Sign):
    """
    用户注册
    限流: 每分钟最多5次
    """
    item_dict = item.dict()
    logger.info(f"注册请求: {item_dict['user']}")

    try:
        # 验证邮箱验证码
        if item_dict.get('code'):
            stored_code = redis.r_get(f"email_code:{item_dict['email']}")
            if not stored_code or stored_code != item_dict['code']:
                return {"success": False, "message": "验证码错误或已过期"}

        # 检查用户名是否已存在
        sql = "SELECT * FROM user WHERE username = %s"
        existing_users = mysql.mysql_output_data(sql, (item_dict['user'],))
        if existing_users:
            return {"success": False, "message": "用户名已存在"}

        # 检查邮箱是否已注册
        sql = "SELECT * FROM user WHERE email = %s"
        existing_emails = mysql.mysql_output_data(sql, (item_dict['email'],))
        if existing_emails:
            return {"success": False, "message": "邮箱已被注册"}

        # 加密密码
        hashed_password = hash_password(item_dict['passwd'])

        # 插入新用户
        user_data = {
            'username': item_dict['user'],
            'password': hashed_password,
            'email': item_dict['email'],
            'login_time': int(time.time())
        }

        result = mysql.mysql_insert_data('user', user_data)
        if result:
            # 删除已使用的验证码
            if item_dict.get('code'):
                redis.r_del(f"email_code:{item_dict['email']}")

            logger.info(f"用户注册成功: {item_dict['user']}")
            return {"success": True, "message": "注册成功"}
        else:
            return {"success": False, "message": "注册失败"}
    except Exception as e:
        logger.error(f"注册失败: {str(e)}")
        raise HTTPException(status_code=500, detail="注册失败")


@app.post('/h5/contact/login')
@limiter.limit("10/minute")
async def contactLogin(request: Request, item: User):
    """
    用户登录
    限流: 每分钟最多10次
    """
    item_dict = item.dict()
    username = item_dict['user']
    password = item_dict['passwd']

    logger.info(f"登录请求: {username}")

    try:
        # 查询用户信息
        sql = "SELECT * FROM user WHERE username = %s"
        users = mysql.mysql_output_data(sql, (username,))

        if not users:
            logger.warning(f"登录失败: 用户不存在 - {username}")
            return {"success": False, "message": "用户名或密码错误"}

        user = users[0]

        # 验证密码
        # 注意：如果数据库中存储的是旧的 SHA-256 密码，需要先迁移
        # 这里同时支持新旧两种密码格式
        password_valid = False
        stored_password = user.get('password')

        # 尝试 bcrypt 验证（新格式）
        if stored_password.startswith('$2b$'):
            password_valid = verify_password(password, stored_password)
        else:
            # 兼容旧的 SHA-256 格式
            import hashlib
            sha256_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            password_valid = (stored_password == sha256_password)

            # 如果验证通过，将密码升级为 bcrypt 格式
            if password_valid:
                new_hashed_password = hash_password(password)
                update_sql = "UPDATE user SET password = %s WHERE id = %s"
                mysql.mysql_conn.cursor().execute(update_sql, (new_hashed_password, user['id']))
                mysql.mysql_conn.commit()
                logger.info(f"密码已升级为 bcrypt 格式: {username}")

        if password_valid:
            # 更新登录时间
            login_time = int(time.time())
            update_sql = "UPDATE user SET login_time = %s WHERE id = %s"
            mysql.mysql_conn.cursor().execute(update_sql, (login_time, user['id']))
            mysql.mysql_conn.commit()

            # 生成 Token
            token = encode_auth_token(user['id'], user['username'])

            logger.info(f"登录成功: {username}")
            return {
                "success": True,
                "message": "登录成功",
                "token": token,
                "user_id": user['id'],
                "username": user['username']
            }
        else:
            logger.warning(f"登录失败: 密码错误 - {username}")
            return {"success": False, "message": "用户名或密码错误"}

    except Exception as e:
        logger.error(f"登录错误: {str(e)}")
        raise HTTPException(status_code=500, detail="登录失败")


@app.post('/h5/contact/list')
@limiter.limit("30/minute")
async def contactList(request: Request, item: ContactParams, user_info: dict = Depends(verify_token)):
    """
    获取联系人列表
    需要认证
    限流: 每分钟最多30次
    """
    logger.info(f"用户 {user_info['user']['username']} 请求联系人列表")

    try:
        sql = "SELECT * FROM list ORDER BY `initial`"
        data = mysql.mysql_output_data(sql)

        return {
            "data": data if data else [],
            "success": True,
            "user_id": user_info['user']['id']
        }
    except Exception as e:
        logger.error(f"获取联系人列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail="获取联系人列表失败")


@app.post('/h5/contact/info')
@limiter.limit("30/minute")
async def contactInfo(request: Request, item: ContactParams, user_info: dict = Depends(verify_token)):
    """
    获取联系人详情
    需要认证
    限流: 每分钟最多30次
    """
    item_dict = item.dict()
    logger.info(f"用户 {user_info['user']['username']} 请求联系人详情: {item_dict.get('id')}")

    try:
        if not item_dict.get('id'):
            return {"success": False, "message": "缺少联系人ID"}

        sql = "SELECT * FROM list WHERE id = %s"
        data = mysql.mysql_output_data(sql, (item_dict['id'],))

        if data:
            return {
                "data": data[0],
                "success": True,
                "user_id": user_info['user']['id']
            }
        else:
            return {"success": False, "message": "联系人不存在"}
    except Exception as e:
        logger.error(f"获取联系人详情失败: {str(e)}")
        raise HTTPException(status_code=500, detail="获取联系人详情失败")


@app.get('/h5/contact/userinfo')
@limiter.limit("20/minute")
async def getUserInfo(request: Request, user_info: dict = Depends(verify_token)):
    """
    获取当前登录用户信息
    需要认证
    限流: 每分钟最多20次
    """
    try:
        user = user_info['user']
        return {
            "success": True,
            "data": {
                "user_id": user['id'],
                "username": user['username'],
                "email": user.get('email', ''),
                "login_time": user.get('login_time', '')
            }
        }
    except Exception as e:
        logger.error(f"获取用户信息失败: {str(e)}")
        raise HTTPException(status_code=500, detail="获取用户信息失败")


@app.post('/h5/contact/verify')
@limiter.limit("20/minute")
async def verifyToken(request: Request, user_info: dict = Depends(verify_token)):
    """
    验证 Token 有效性
    需要认证
    限流: 每分钟最多20次
    """
    return {
        "success": True,
        "message": "Token有效",
        "user_id": user_info['user']['id'],
        "exp": user_info['payload'].get('exp')
    }


@app.post('/h5/contact/ocr')
@limiter.limit("5/minute")
async def contactOCR(request: Request, item: ContactParams, user_info: dict = Depends(verify_token)):
    """
    百度 OCR 识别服务
    需要认证
    限流: 每分钟最多5次

    注意：需要在 .env 中配置百度 API 凭据
    """
    logger.info(f"用户 {user_info['user']['username']} 请求 OCR 功能")

    try:
        # 百度 OCR API 配置（从环境变量读取）
        client_id = config.DB_CONFIG.get('BAIDU_API_KEY', '')
        client_secret = config.DB_CONFIG.get('BAIDU_SECRET_KEY', '')

        if not client_id or not client_secret:
            return {
                "success": False,
                "message": "百度 OCR API 未配置",
                "user_id": user_info['user']['id']
            }

        # 获取 access_token
        url = f"https://aip.baidubce.com/oauth/2.0/token?client_id={client_id}&client_secret={client_secret}&grant_type=client_credentials"
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }
        response = requests.post(url, headers=headers, timeout=10)

        return {
            "success": True,
            "message": "OCR 服务可用",
            "user_id": user_info['user']['id'],
            "data": response.json() if response.status_code == 200 else None
        }
    except Exception as e:
        logger.error(f"OCR 服务错误: {str(e)}")
        raise HTTPException(status_code=500, detail="OCR 服务调用失败")


# ==================== 健康检查 ====================

@app.get('/health')
async def health_check():
    """健康检查接口"""
    try:
        # 检查数据库连接
        sql = "SELECT 1"
        mysql.mysql_query_data(sql)
        db_status = "healthy"
    except:
        db_status = "unhealthy"

    try:
        # 检查 Redis 连接
        redis.redis_conn.ping()
        redis_status = "healthy"
    except:
        redis_status = "unhealthy"

    return {
        "status": "running",
        "database": db_status,
        "redis": redis_status,
        "version": "2.0.0"
    }


# ==================== 启动事件 ====================

@app.on_event("startup")
async def startup_event():
    """应用启动时的事件"""
    logger.info("=" * 50)
    logger.info("联系人管理系统 API 启动成功")
    logger.info("版本: 2.0.0")
    logger.info("环境: " + ("开发" if config.DEBUG else "生产"))
    logger.info("=" * 50)


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时的事件"""
    logger.info("联系人管理系统 API 正在关闭...")
    # 关闭数据库连接
    try:
        mysql.mysql_conn.close()
        redis.redis_conn.close()
        logger.info("数据库连接已关闭")
    except:
        pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8080,
        reload=config.DEBUG
    )
