#!/usr/bin/env
#coding=utf-8

import os
from typing import Dict, Any

class Config:
    """应用配置类"""
    
    # JWT配置
    SECRET_KEY = os.getenv("JWT_SECRET_KEY", "telphone-h5-service-secret-key-2024-change-in-production")
    JWT_ALGORITHM = "HS256"
    JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))
    
    # 数据库配置
    DB_CONFIG: Dict[str, Any] = {
        'host': os.getenv("DB_HOST", "127.0.0.1"),
        'port': int(os.getenv("DB_PORT", "3306")),
        'user': os.getenv("DB_USER", "root"),
        'password': os.getenv("DB_PASSWORD", "lovemysql"),
        'database': os.getenv("DB_NAME", "contact"),
        'charset': os.getenv("DB_CHARSET", "utf8mb4")
    }
    
    # Redis配置
    REDIS_CONFIG: Dict[str, Any] = {
        'host': os.getenv("REDIS_HOST", "127.0.0.1"),
        'port': int(os.getenv("REDIS_PORT", "6379")),
        'db': int(os.getenv("REDIS_DB", "0")),
        'password': os.getenv("REDIS_PASSWORD", "loveredis"),
        'decode_responses': True
    }
    
    # 邮件配置
    EMAIL_CONFIG: Dict[str, Any] = {
        'host': os.getenv("EMAIL_HOST", "smtp.163.com"),
        'port': int(os.getenv("EMAIL_PORT", "25")),
        'user': os.getenv("EMAIL_USER", ""),
        'password': os.getenv("EMAIL_PASSWORD", ""),
        'sender': os.getenv("EMAIL_SENDER", "")
    }
    
    # 应用配置
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")

# 全局配置实例
config = Config()