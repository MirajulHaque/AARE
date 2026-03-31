/*
 * Adaptive Anti-Replay Engine (AARE)
 * ----------------------------------
 * A Burp Suite extension for bypassing dynamic anti-replay and CSRF protections.
 *
 * Author: Md Mirajul Haque Miraj
 * Title: Cybersecurity Consultant
 * LinkedIn: https://www.linkedin.com/in/mdmirajulhaque/
 *
 * Description:
 * This extension automates token regeneration by extracting dynamic values
 * from server responses and injecting them into outgoing requests.
 *
 * Disclaimer:
 * This tool is intended for authorized security testing and research purposes only.
 */

/*
 * Adaptive Anti-Replay Engine (AARE)
 * ----------------------------------
 * Author: Md Mirajul Haque Miraj
 */

import burp.*;

import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Base64;

public class BurpExtender implements IBurpExtender, IHttpListener, ITab {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel panel;
    private JCheckBox toggle;
    private JCheckBox replayMode;
    private JTextField hostField;
    private JTextField pathField;
    private JTextField requestHeaderField;
    private JTextField responseHeaderField;
    private JTextArea logArea;

    private volatile boolean enabled = true;

    private final Map<String, AdaptiveToken> adaptiveCache = new ConcurrentHashMap<>();
    private final Map<String, Object> hostLocks = new ConcurrentHashMap<>();

    // 🔥 Prevent log spam
    private final Set<String> missingHeaderLogged = ConcurrentHashMap.newKeySet();

    private static class AdaptiveToken {
        String token;
        long createdAt;
        long ttl = 3000;

        AdaptiveToken(String token) {
            this.token = token;
            this.createdAt = System.currentTimeMillis();
        }

        boolean isValid() {
            return (System.currentTimeMillis() - createdAt) < ttl;
        }

        void updateTTLOnFailure() {
            long observed = System.currentTimeMillis() - createdAt;
            ttl = Math.max(500, observed - 200);
        }
    }

    private Object getLock(String host) {
        return hostLocks.computeIfAbsent(host, k -> new Object());
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("AARE - Adaptive Anti-Replay Engine");

        initUI();

        callbacks.registerHttpListener(this);
        callbacks.addSuiteTab(this);

        log("[+] AARE loaded successfully");
        log("[+] Version: v1.0.0");
    }

    private void initUI() {
        panel = new JPanel(new BorderLayout());

        JPanel top = new JPanel();

        toggle = new JCheckBox("Enable", true);
        toggle.addActionListener(e -> {
            enabled = toggle.isSelected();
            missingHeaderLogged.clear(); // reset logs
        });

        replayMode = new JCheckBox("Replay Mode", false);

        hostField = new JTextField("", 12);
        pathField = new JTextField("", 12);
        requestHeaderField = new JTextField("", 15);
        responseHeaderField = new JTextField("", 15);

        JButton clearLogs = new JButton("Clear Logs");
        clearLogs.addActionListener(e -> logArea.setText(""));

        top.add(toggle);
        top.add(replayMode);
        top.add(new JLabel("Host:"));
        top.add(hostField);
        top.add(new JLabel("Path:"));
        top.add(pathField);
        top.add(new JLabel("Req:"));
        top.add(requestHeaderField);
        top.add(new JLabel("Resp:"));
        top.add(responseHeaderField);
        top.add(clearLogs);

        panel.add(top, BorderLayout.NORTH);

        logArea = new JTextArea();
        panel.add(new JScrollPane(logArea), BorderLayout.CENTER);
    }

    @Override
    public String getTabCaption() {
        return "AARE";
    }

    @Override
    public Component getUiComponent() {
        return panel;
    }

    private void log(String msg) {
        callbacks.printOutput(msg);
        logArea.append(msg + "\n");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        if (!enabled || !messageIsRequest) return;

        IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);

        for (String h : reqInfo.getHeaders()) {
            if (h.startsWith("X-AARE-Internal")) return;
        }

        String host = reqInfo.getUrl().getHost();
        String path = reqInfo.getUrl().getPath();

        if (!hostField.getText().isEmpty() && !host.contains(hostField.getText())) return;
        if (!pathField.getText().isEmpty() && !path.contains(pathField.getText())) return;

        if (reqInfo.getHeaders().toString().contains("X-AARE-Handled")) return;

        try {
            byte[] modified = applyToken(messageInfo, host);
            if (modified == null) return;

            messageInfo.setRequest(modified);

            IHttpRequestResponse check = callbacks.makeHttpRequest(messageInfo.getHttpService(), modified);
            if (check.getResponse() == null) return;

            IResponseInfo respInfo = helpers.analyzeResponse(check.getResponse());

            if (respInfo.getStatusCode() == 401) {
                log("[!] 401 detected on " + host + " → retrying");

                AdaptiveToken entry = adaptiveCache.get(host);
                if (entry != null) entry.updateTTLOnFailure();

                adaptiveCache.remove(host);

                byte[] retry = applyToken(messageInfo, host);
                if (retry != null) messageInfo.setRequest(retry);
            }

        } catch (Exception e) {
            log("[-] Error: " + e.getMessage());
        }
    }

    private byte[] applyToken(IHttpRequestResponse messageInfo, String host) {

        String reqHeaderName = requestHeaderField.getText().trim();

        if (reqHeaderName.isEmpty()) {
            if (!missingHeaderLogged.contains(host)) {
                log("[-] Request header not set for host: " + host);
                missingHeaderLogged.add(host);
            }
            return null;
        }

        try {
            String token = replayMode.isSelected()
                    ? getCachedToken(host)
                    : getAdaptiveToken(messageInfo, host);

            if (token == null) return null;

            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            List<String> headers = reqInfo.getHeaders();

            List<String> newHeaders = new ArrayList<>();
            boolean found = false;

            for (String h : headers) {
                if (h.toLowerCase().startsWith(reqHeaderName.toLowerCase() + ":")) {
                    newHeaders.add(reqHeaderName + ": " + token);
                    found = true;
                } else {
                    newHeaders.add(h);
                }
            }

            if (!found) {
                newHeaders.add(reqHeaderName + ": " + token);
            }

            newHeaders.add("X-AARE-Handled: true");

            byte[] body = messageInfo.getRequest();
            int offset = reqInfo.getBodyOffset();

            return helpers.buildHttpMessage(
                    newHeaders,
                    Arrays.copyOfRange(body, offset, body.length)
            );

        } catch (Exception e) {
            log("[-] Apply error: " + e.getMessage());
            return null;
        }
    }

    private String getAdaptiveToken(IHttpRequestResponse messageInfo, String host) {

        AdaptiveToken entry = adaptiveCache.get(host);

        if (entry != null && entry.isValid()) return entry.token;

        synchronized (getLock(host)) {

            entry = adaptiveCache.get(host);
            if (entry != null && entry.isValid()) return entry.token;

            String token = generateToken(messageInfo);
            if (token == null) return null;

            log("[+] Token generated for " + host);

            adaptiveCache.put(host, new AdaptiveToken(token));
            return token;
        }
    }

    private String getCachedToken(String host) {
        AdaptiveToken entry = adaptiveCache.get(host);
        return entry != null ? entry.token : null;
    }

    private String generateToken(IHttpRequestResponse messageInfo) {

        try {
            IRequestInfo reqInfo = helpers.analyzeRequest(messageInfo);
            IHttpService service = messageInfo.getHttpService();

            List<String> headers = new ArrayList<>();
            headers.add("OPTIONS " + reqInfo.getUrl().getFile() + " HTTP/1.1");
            headers.add("Host: " + reqInfo.getUrl().getHost());
            headers.add("X-AARE-Internal: true");

            for (String h : reqInfo.getHeaders()) {
                if (h.toLowerCase().startsWith("authorization") ||
                    h.toLowerCase().startsWith("cookie") ||
                    h.toLowerCase().startsWith("origin")) {
                    headers.add(h);
                }
            }

            byte[] optionsReq = helpers.buildHttpMessage(headers, new byte[0]);
            IHttpRequestResponse response = callbacks.makeHttpRequest(service, optionsReq);

            if (response.getResponse() == null) return null;

            IResponseInfo respInfo = helpers.analyzeResponse(response.getResponse());

            String targetHeader = responseHeaderField.getText().trim().toLowerCase();
            String raw = null;

            if (targetHeader.isEmpty()) {
                log("[*] Using heuristic detection");
            }

            for (String h : respInfo.getHeaders()) {
                if (!targetHeader.isEmpty() && h.toLowerCase().startsWith(targetHeader + ":")) {
                    raw = h.split(":", 2)[1].trim();
                    break;
                }
            }

            if (raw == null && targetHeader.isEmpty()) {
                for (String h : respInfo.getHeaders()) {
                    if (h.length() > 50 && h.contains(":")) {
                        String val = h.split(":", 2)[1].trim();
                        if (val.matches("^[A-Za-z0-9+/=]+$") && val.length() > 40) {
                            log("[+] Heuristic header detected");
                            raw = val;
                            break;
                        }
                    }
                }
            }

            if (raw == null) {
                log("[-] Token header not found");
                return null;
            }

            return Base64.getEncoder().encodeToString(
                    Base64.getEncoder().encode(raw.getBytes())
            );

        } catch (Exception e) {
            log("[-] Token error: " + e.getMessage());
            return null;
        }
    }
}
