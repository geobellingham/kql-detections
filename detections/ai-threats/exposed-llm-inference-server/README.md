# Self-hosted LLM inference server exposed to the internet

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/exposed-llm-inference-server.kql`](../../../tests/fixtures/exposed-llm-inference-server.kql) · regex tests: [`tests/regex_test.py`](../../../tests/regex_test.py) |
| **Data** | `CommonSecurityLog` (FortiGate traffic + UTM web logs) |
| **ATT&CK** | T1190 Exploit Public-Facing Application, T1496 Resource Hijacking, T1071.001 Web Protocols |
| **Severity** | High (inbound with inference API calls or > 100 KB returned), Medium otherwise |
| **Runs** | Hourly over 1 hour |

## Goal
Find shadow-AI inference servers that are reachable from the internet before attackers do. Also find internal hosts quietly using **someone else's** exposed server.

## Why
Ollama, LM Studio, text-generation-webui and ComfyUI are installed in minutes, often on a GPU workstation or a forgotten VM, and **ship without authentication**. Internet-wide scans find thousands of exposed Ollama instances on port 11434. Attackers use them for free inference (LLMjacking), as reasoning engines for their own tooling, or to pull, overwrite or poison models (`/api/pull`, `/api/create`, `/api/push`).

## Strategy
1. FortiGate sessions that were **allowed**, to an inference port (11434 Ollama, 1234 LM Studio, 7860 Gradio/TGWUI, 8188 ComfyUI) **or** to an inference API path (`/api/generate|chat|tags|pull|push|create|embed|show|ps`, `/v1/chat/completions|completions|models|embeddings`) when UTM web logging provides the URL.
2. **Inbound:** public source → internal host (or one of `ownedPublicRanges`, for firewalls that log the pre-NAT VIP). Grouped per internal host, with the number of distinct external sources, the paths used and the bytes returned. Model output volume shows actual use, not just a scan.
3. **Outbound:** internal host → public IP on an inference **port**. Paths alone don't count outbound, since `/v1/chat/completions` to OpenAI/Azure is normal SaaS use.

## Technical context
- Port 1234 and 7860 are also used by other software. Path matches carry more weight, which is why they make the inbound alert High.
- FortiGate `ReceivedBytes` is what the *source* received, so for inbound sessions it's what the server sent back.
- The path regex is unit-tested: `/api/chat` matches, `/api/chatbot-config` and `/api/generated-reports` don't.

## Blind spots
- Servers on non-default ports without UTM URL logging.
- Exposure through a reverse proxy or tunnel (ngrok, Cloudflare Tunnel) that doesn't pass through the firewall. Catch those on the endpoint (`DeviceNetworkEvents` listening on 11434, or `ollama serve` with `OLLAMA_HOST=0.0.0.0`).
- Inference servers in cloud VPCs/VNets that don't log to this FortiGate. Use the cloud flow logs.

## False positives
- Internal AI platforms intentionally published behind authentication. Add them to `approvedInferenceHosts`.
- Other services that happen to use port 1234/7860/8188. Check `Paths` and the host owner.

## Validation
- **Synthetic:** `node tools/render-test.js exposed-llm-inference-server`. Expected: 10.0.5.20 inbound High, 10.0.8.15 outbound Medium; denied, SaaS and non-Fortinet rows silent.
- **Live, lab:** run `OLLAMA_HOST=0.0.0.0 ollama serve` behind a test VIP and request `/api/tags` from an outside host.

## Response
1. Block the port at the firewall, then find the owner of the internal host.
2. Assume the server was used by others. Check its logs for `/api/pull`, `/api/create` and `/api/push`: models may have been replaced or poisoned, so don't trust them.
3. If it's needed, re-publish behind authentication (reverse proxy with SSO) on an approved host.
4. **Outbound case:** find which process on the internal host talked to the external server (`DeviceNetworkEvents`). It's either a user's shadow-AI tool or malware using stolen compute.
