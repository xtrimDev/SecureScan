import asyncio
import subprocess
import os
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = FastAPI()

# Get frontend URL from environment variable
frontend_url = os.getenv('FRONTEND_URL')

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws/ping")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        while True:
            message = await websocket.receive_text()

            if message.startswith("xss:"):
                url = message.split("xss:", 1)[1].strip()
                process = await asyncio.create_subprocess_exec(
                    "python3", "xsstrike/xsstrike.py", "-u", url, '--crawl', '-l', '3',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    await websocket.send_text(f"xss:{line.decode().strip()}")
                await process.wait()
                await websocket.send_text("xss:XSStrike scan completed.")
            elif message.startswith("sql:"):
                url = message.split("sql:", 1)[1].strip()
                process = await asyncio.create_subprocess_exec(
                    "python3", "sqlmap/sqlmap.py", "-u", url, '--batch', '--level=3', '--risk=3', '--crawl=3', '--random-agent', '--threads=5', '--banner', '--dbs',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    await websocket.send_text(f"sql:{line.decode().strip()}")
                await process.wait()
                await websocket.send_text("sql:sqlmap scan completed.")
            else:
                await websocket.send_text("Unknown command.")
    except Exception as e:
        await websocket.send_text(f"Error: {str(e)}")
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
