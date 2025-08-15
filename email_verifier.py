cat > email_verifier.py << 'EOF'
#!/usr/bin/env python3
"""
个人邮件验证器 - Railway优化版本
"""

import asyncio
import dns.resolver
import time
import json
import sqlite3
import random
import re
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VerificationResult:
    email: str
    is_valid: bool
    status_code: Optional[int] = None
    server_response: str = ""
    mx_records: List[str] = None
    verification_time: float = 0.0
    timestamp: datetime = None
    error_message: Optional[str] = None
    cached: bool = False
    
    def __post_init__(self):
        if self.mx_records is None:
            self.mx_records = []
        if self.timestamp is None:
            self.timestamp = datetime.now()

class EmailVerifier:
    def __init__(self):
        # 数据库路径 - Railway友好
        db_dir = os.getenv("DATABASE_DIR", "/tmp")
        self.db_path = os.path.join(db_dir, "email_verification.db")
        self.setup_database()
        
        # 缓存配置
        cache_hours = int(os.getenv("CACHE_DURATION_HOURS", "24"))
        self.cache_duration = timedelta(hours=cache_hours)
        
        # SMTP配置 - 从环境变量读取
        self.smtp_timeout = int(os.getenv("SMTP_TIMEOUT", "15"))
        self.max_concurrent = int(os.getenv("MAX_CONCURRENT", "2"))
        
        # 发送方配置
        self.sender_configs = [
            {
                'email': 'validator@emailcheck.tech',
                'helo': 'mail-validator-1.emailcheck.tech'
            },
            {
                'email': 'checker@emailcheck.tech', 
                'helo': 'mail-validator-2.emailcheck.tech'
            },
            {
                'email': 'verify@emailcheck.tech',
                'helo': 'mail-validator-3.emailcheck.tech'
            }
        ]
        self.current_sender = 0
        
        # DNS解析器配置
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 8
        self.dns_resolver.lifetime = 8

    def setup_database(self):
        try:
            # 确保目录存在
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
            self.conn.execute('''
                CREATE TABLE IF NOT EXISTS verifications (
                    email TEXT PRIMARY KEY,
                    is_valid BOOLEAN,
                    status_code INTEGER,
                    server_response TEXT,
                    mx_records TEXT,
                    verification_time REAL,
                    timestamp TEXT,
                    error_message TEXT
                )
            ''')
            self.conn.commit()
            logger.info(f"✅ 数据库初始化完成: {self.db_path}")
        except Exception as e:
            logger.error(f"❌ 数据库初始化失败: {e}")
            raise

    def is_valid_email_format(self, email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def get_mx_records(self, domain: str) -> List[str]:
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            sorted_mx = sorted(mx_records, key=lambda x: x.preference)
            return [str(mx.exchange).rstrip('.') for mx in sorted_mx]
        except Exception as e:
            logger.debug(f"获取MX记录失败 {domain}: {e}")
            return []

    def get_cached_result(self, email: str) -> Optional[VerificationResult]:
        try:
            cursor = self.conn.cursor()
            cutoff_time = (datetime.now() - self.cache_duration).isoformat()
            
            cursor.execute(
                'SELECT * FROM verifications WHERE email = ? AND timestamp > ?',
                (email, cutoff_time)
            )
            row = cursor.fetchone()
            
            if row:
                result = VerificationResult(
                    email=row[0],
                    is_valid=bool(row[1]),
                    status_code=row[2],
                    server_response=row[3],
                    mx_records=json.loads(row[4]) if row[4] else [],
                    verification_time=row[5],
                    timestamp=datetime.fromisoformat(row[6]),
                    error_message=row[7],
                    cached=True
                )
                logger.info(f"📚 缓存命中: {email}")
                return result
        except Exception as e:
            logger.error(f"读取缓存失败: {e}")
        return None

    def cache_result(self, result: VerificationResult):
        try:
            self.conn.execute('''
                INSERT OR REPLACE INTO verifications 
                (email, is_valid, status_code, server_response, mx_records, 
                 verification_time, timestamp, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                result.email,
                result.is_valid,
                result.status_code,
                result.server_response,
                json.dumps(result.mx_records),
                result.verification_time,
                result.timestamp.isoformat(),
                result.error_message
            ))
            self.conn.commit()
        except Exception as e:
            logger.error(f"缓存结果失败: {e}")

    def get_next_sender(self) -> Dict[str, str]:
        sender = self.sender_configs[self.current_sender]
        self.current_sender = (self.current_sender + 1) % len(self.sender_configs)
        return sender

    async def smtp_verify(self, email: str, mx_host: str) -> Tuple[bool, int, str]:
        sender = self.get_next_sender()
        
        try:
            # 建立连接
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(mx_host, 25),
                timeout=self.smtp_timeout
            )
            
            # 读取欢迎消息
            welcome = await asyncio.wait_for(reader.readline(), timeout=8)
            if not welcome.startswith(b'220'):
                raise Exception(f"SMTP连接失败")
            
            # EHLO命令
            helo_cmd = f"EHLO {sender['helo']}\r\n"
            writer.write(helo_cmd.encode())
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=8)
            
            # MAIL FROM命令
            mail_cmd = f"MAIL FROM:<{sender['email']}>\r\n"
            writer.write(mail_cmd.encode())
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=8)
            
            # RCPT TO命令（关键验证）
            rcpt_cmd = f"RCPT TO:<{email}>\r\n"
            writer.write(rcpt_cmd.encode())
            await writer.drain()
            
            rcpt_response = await asyncio.wait_for(reader.readline(), timeout=10)
            rcpt_str = rcpt_response.decode().strip()
            
            # 优雅退出
            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()
            
            try:
                await writer.wait_closed()
            except:
                pass
            
            # 解析响应
            try:
                status_code = int(rcpt_str[:3])
            except:
                status_code = 500
            
            is_valid = status_code in [250, 251]
            return is_valid, status_code, rcpt_str
            
        except asyncio.TimeoutError:
            return False, 0, "连接超时"
        except Exception as e:
            return False, 0, str(e)

    async def verify_email(self, email: str) -> VerificationResult:
        start_time = time.time()
        
        # 检查缓存
        cached_result = self.get_cached_result(email)
        if cached_result:
            return cached_result
        
        # 格式验证
        if not self.is_valid_email_format(email):
            result = VerificationResult(
                email=email,
                is_valid=False,
                error_message="邮箱格式无效",
                verification_time=time.time() - start_time
            )
            self.cache_result(result)
            return result
        
        domain = email.split('@')[1].lower()
        
        # 获取MX记录
        mx_records = self.get_mx_records(domain)
        if not mx_records:
            result = VerificationResult(
                email=email,
                is_valid=False,
                mx_records=[],
                server_response="未找到MX记录",
                error_message="域名没有MX记录",
                verification_time=time.time() - start_time
            )
            self.cache_result(result)
            return result
        
        # SMTP验证
        primary_mx = mx_records[0]
        try:
            is_valid, status_code, response = await self.smtp_verify(email, primary_mx)
            
            result = VerificationResult(
                email=email,
                is_valid=is_valid,
                status_code=status_code,
                server_response=response,
                mx_records=mx_records,
                verification_time=time.time() - start_time
            )
        except Exception as e:
            result = VerificationResult(
                email=email,
                is_valid=False,
                mx_records=mx_records,
                error_message=str(e),
                verification_time=time.time() - start_time
            )
        
        # 缓存结果
        self.cache_result(result)
        return result

    def get_stats(self) -> Dict:
        try:
            cursor = self.conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM verifications')
            total = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM verifications WHERE is_valid = 1')
            valid = cursor.fetchone()[0]
            
            cutoff = (datetime.now() - timedelta(hours=24)).isoformat()
            cursor.execute('SELECT COUNT(*) FROM verifications WHERE timestamp > ?', (cutoff,))
            recent = cursor.fetchone()[0]
            
            return {
                'total_verifications': total,
                'valid_emails': valid,
                'invalid_emails': total - valid,
                'recent_24h': recent,
                'success_rate': f"{(valid/total*100):.1f}%" if total > 0 else "0%"
            }
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {}
EOF