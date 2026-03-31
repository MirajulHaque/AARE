# Adaptive Anti-Replay Engine (AARE)

Developed by Md Mirajul Haque Miraj — Cybersecurity Consultant

Adaptive Anti-Replay Engine (AARE) is an advanced Burp Suite extension designed to bypass modern anti-replay and dynamic request validation mechanisms by automatically regenerating short-lived tokens.

This tool is intended for security professionals, red teamers, and penetration testers working with APIs protected by dynamic request verification techniques.

## ⚡ Quick Start (Recommended)

1. Download the latest release file: AARE.jar

2. Open Burp Suite

3. Navigate to:
   Extender → Extensions → Add

4. Configure:
   Type: Java  
   Select: AARE.jar  

5. Enable the extension and configure target-specific parameters

## 🚀 Features

- Adaptive token regeneration with dynamic TTL learning  
- Automatic retry on authentication failure (401 response)  
- Fully customizable request and response header support  
- Heuristic detection for unknown or obfuscated token headers  
- Replay simulation mode for testing anti-replay protections  
- Thread-safe design suitable for Intruder and high-volume testing  
- Internal request isolation to prevent recursion and infinite loops  
- Built-in logging panel for real-time debugging  
- Clear Logs button for resetting extension logs instantly  

## ⚙️ How It Works

Many modern APIs implement anti-replay or anti-automation protections using dynamically generated tokens. These tokens are typically:

- Generated per request or session  
- Embedded in headers or responses  
- Short-lived (expires within seconds)  
- Required for subsequent API calls  

AARE automates the entire process:

1. Intercepts an outgoing HTTP request  
2. Sends a preflight request (commonly OPTIONS or similar)  
3. Extracts a dynamic value from the response headers  
4. Applies required encoding logic (default: double Base64)  
5. Injects the generated value into the target request header  
6. Sends the modified request  
7. If the request fails (e.g., 401 Unauthorized), it regenerates and retries automatically  

## 🧪 Usage

Configure the extension inside Burp Suite:

| Setting | Description |
|--------|------------|
| Enable | Activate or deactivate the extension |
| Replay Mode | OFF for bypass, ON for testing replay protections |
| Host | Target API domain (e.g., api.example.com) |
| Path | Optional endpoint filter |
| Request Header | Header where the token will be injected |
| Response Header | Header from which the token will be extracted |

## 🔍 Identifying the Correct Headers

### Request Header

Look for headers that:
- Change frequently  
- Appear encoded or randomized  
- Are required for request validation  

Examples:
- Authorization  
- X-CSRF-Token  
- X-Auth-Token  
- X-Request-Signature  
- Custom headers (e.g., Sxsrf, Nxsrf, Cusxsrf)  

### Response Header

Look for headers that:
- Change per request  
- Contain long encoded values  
- Appear in preflight or initial responses  

These are often:
- API-generated tokens  
- CDN/WAF validation headers  
- Backend-generated dynamic values  

## 🧠 Logging and Debugging

AARE includes a built-in logging panel to help analyze behavior in real time.

- Logs token generation events  
- Logs retry attempts  
- Shows errors and fallback behavior  

You can use the **Clear Logs** button to reset logs during testing and keep the output clean.

## 🧠 Replay Mode (Research Feature)

Replay Mode allows testing of anti-replay protections.

When enabled:
- Tokens are reused intentionally  
- Helps identify:
  - Weak replay protection  
  - Token reuse vulnerabilities  
  - Improper session binding  

## 🛠 Build from Source

javac -cp burpsuite_pro.jar src/BurpExtender.java  
jar cf build/AARE.jar *.class  

## 📁 Project Structure

AARE/  
├── src/  
│   └── BurpExtender.java  
├── build/  
│   └── AARE.jar  
├── docs/  
│   └── USAGE.md  
├── README.md  
├── LICENSE  
├── .gitignore  

## ⚠️ Important Notes

- Replay Mode is intended for testing only  
- Correct header identification is critical  
- Behavior depends on backend protection mechanisms  

## 🔐 Disclaimer

This tool is intended strictly for authorized security testing and research purposes.

The author is not responsible for misuse or unauthorized activity.

## 👨‍💻 Author

Md Mirajul Haque Miraj  
Cybersecurity Consultant  

LinkedIn: https://www.linkedin.com/in/mdmirajulhaque/

## 📜 License

MIT License  

## ⭐ Support

If you find this tool useful:

- Star the repository  
- Contribute improvements  
- Share feedback  

## 🚀 Future Improvements

- Encoding strategy selector  
- Automatic header detection  
- Multi-target profiles  
- Advanced replay simulation  
- UI enhancements  
