@echo off
chcp 65001 >nul
echo ================================
echo  网络拓扑管理系统 - 后端服务
echo ================================
echo.

REM 检查 Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未找到 Python，请先安装 Python 3.8+
    pause
    exit /b 1
)

REM 安装依赖
echo [1/2] 安装 Python 依赖...
pip install flask flask-cors paramiko -q

echo [2/2] 启动 API 服务...
echo.
echo  访问地址: http://localhost:5000
echo  健康检查: http://localhost:5000/api/health
echo  演示数据: http://localhost:5000/api/topology/demo
echo.
python app.py
pause
