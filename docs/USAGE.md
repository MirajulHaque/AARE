# AARE Usage Guide

This document provides a detailed, practical guide on how to use Adaptive Anti-Replay Engine (AARE) during real-world security testing.

## 🎯 Purpose

AARE is designed to automate bypassing of dynamic anti-replay and request validation mechanisms in modern APIs.

It is particularly useful when:
- Tokens expire quickly (seconds)
- Tokens must be generated per request
- Manual replay fails due to missing dynamic values

## ⚙️ Basic Workflow

1. Intercept a valid request using Burp Proxy  
2. Send the request to Repeater  
3. Identify failure behavior (typically 401 Unauthorized)  
4. Enable AARE  
5. Configure required headers  
6. Resend request  
7. Verify successful response (e.g., 200 OK)  

## 🔍 Step 1: Capture a Valid Request

Use Burp Proxy to capture a request from:
- Browser  
- Mobile application  
- API client  

Ensure:
- The request is working in its original context  
- Required headers are present  

## 🔍 Step 2: Send to Repeater

Right-click the request and select:
Send to Repeater  

Now test manually:
- Remove dynamic headers  
- Replay request  

Expected result:
Request fails (e.g., 401 Unauthorized)

## 🔍 Step 3: Identify Dynamic Request Header

Look for headers that:
- Change frequently  
- Appear encoded or random  
- Are required for successful requests  

Common examples (varies by application):
- Authorization  
- X-CSRF-Token  
- X-Auth-Token  
- X-Request-Signature  
- Custom headers (e.g., Sxsrf, Nxsrf, Cusxsrf)  

## 🔍 Step 4: Identify Token Source (Response Header)

Send the request and inspect response headers.

Look for values that:
- Change on each request  
- Are long and high entropy  
- Look encoded (Base64-like)  
- Appear after preflight or initial calls  

These headers may originate from:
- API backend  
- CDN/WAF systems  
- Custom security middleware  

## 🔗 Step 5: Map Dependency

You must confirm the relationship between response and request headers.

Response Header → Request Header  

Test:
1. Capture response header value  
2. Inject it manually into the request  
3. Send the request  

If the request succeeds:
You have identified the correct mapping  

## ⚙️ Step 6: Configure AARE

Open the AARE tab in Burp Suite and configure:

| Setting | Value |
|--------|------|
| Enable | ON |
| Replay Mode | OFF |
| Host | Target domain |
| Path | Optional filter |
| Request Header | Header to inject token |
| Response Header | Header to extract token |

## 🧪 Step 7: Test the Flow

Without AARE:
- Request fails (401)

With AARE:
- Token generated automatically  
- Request succeeds (200)

## 🧠 Logging and Debugging

AARE includes a built-in logging panel to help analyze behavior in real time.

The logs provide insight into:
- Token generation events  
- Retry attempts after failure  
- Heuristic detection usage  
- Error conditions  

### Using Logs Effectively

- Observe logs during initial setup  
- Verify that tokens are being generated  
- Confirm retry behavior on failures  
- Identify misconfiguration quickly  

### Clear Logs Feature

Use the **Clear Logs** button to:

- Reset the log panel  
- Remove previous noise  
- Focus on current test activity  

This is especially useful during:
- Repeated testing  
- Intruder attacks  
- Debugging header configurations  

## 🧠 Replay Mode (Advanced Testing)

Replay Mode is designed for testing anti-replay protections.

When enabled:
- Tokens are reused intentionally  
- No new token is generated  

Expected behavior:
- Secure systems reject reused tokens  
- Weak implementations may accept them  

## 🚀 Using AARE with Intruder

AARE is thread-safe and works with Intruder.

Steps:

1. Send request to Intruder  
2. Configure payload positions  
3. Enable AARE  
4. Start attack  

AARE will:
- Generate tokens per request  
- Prevent token reuse issues  
- Maintain stability under load  

## ⚠️ Common Issues and Fixes

### Still getting 401

Possible causes:
- Incorrect request header  
- Incorrect response header  
- Token encoding mismatch  
- Token expires too quickly  

Fix:
- Re-identify headers  
- Verify response behavior  
- Confirm encoding pattern  

### Request header not set

Cause:
- Request Header field is empty  

Fix:
- Set the correct header name in AARE  

### Token not injected

Check:
- Header name matches exactly  
- Header exists or is correctly added  
- Extension is enabled  

### No token extracted

Check:
- Response header name is correct  
- Header exists in response  
- Try leaving response header empty to use heuristic detection  

### Unexpected behavior

Check:
- Configuration accuracy  
- Host and path filters  
- Extension logs for detailed errors  

## 🔬 Advanced Tips

- Leave Response Header empty to trigger heuristic detection  
- Use Repeater first before Intruder  
- Compare working vs failing requests carefully  
- Monitor logs continuously during testing  
- Use Clear Logs frequently to reduce noise  

## 🧠 When to Use AARE

Use AARE when:
- API uses short-lived tokens  
- Manual replay fails  
- Token is dynamically generated  
- Automation tools fail due to validation logic  

## ⚠️ When Not to Use

Avoid using AARE when:
- Token is static  
- No dynamic validation exists  
- The issue is unrelated to request validation  

## 🔐 Ethical Usage

This tool must only be used in:
- Authorized penetration testing  
- Bug bounty programs (in-scope targets)  
- Security research environments  

Unauthorized use is strictly prohibited  

## 👨‍💻 Author

Md Mirajul Haque Miraj  
Cybersecurity Consultant  

LinkedIn: https://www.linkedin.com/in/mdmirajulhaque/
