cat > main.py << 'EOF'
#!/usr/bin/env python3
"""
Railway部署入口文件
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from email_verifier import EmailVerifier
import uvicorn

# 创建FastAPI应用
app = FastAPI(
    title="个人邮件验证API",
    description="高效的异步邮件验证服务",
    version="1.0.0"
)

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 全局验证器实例
verifier = EmailVerifier()

class EmailRequest(BaseModel):
    email: str

@app.get("/")
async def root():
    return {
        "service": "个人邮件验证API",
        "version": "1.0.0", 
        "status": "运行中",
        "platform": "Railway"
    }

@app.get("/health")
async def health_check():
    try:
        stats = verifier.get_stats()
        return {
            "status": "healthy",
            "database": "connected",
            "stats": stats
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Service unhealthy: {str(e)}")

@app.post("/verify")
async def verify_email(request: EmailRequest):
    try:
        result = await verifier.verify_email(request.email)
        return {
            "email": result.email,
            "is_valid": result.is_valid,
            "status_code": result.status_code,
            "server_response": result.server_response,
            "verification_time": result.verification_time,
            "cached": result.cached,
            "mx_records": result.mx_records[:3]  # 只返回前3个MX记录
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")

@app.get("/stats")
async def get_stats():
    try:
        stats = verifier.get_stats()
        return {"stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
EOF