# Self-hosted LLM inference server exposed to the internet

| | |
|---|---|
| **Rule** | [`rule.yaml`](rule.yaml) · test: [`tests/fixtures/exposed-llm-inference-server.kql`](../../../tests/fixtures/exposed-llm-inference-server.kql) · regex tests: [`tests/regex_test.py`](../../../tests/regex_test.py) |
| **Data** | `CommonSecurityLog` (FortiGate traffic and UTM web logs) |
| **ATT&CK** | T1190 Exploit Public-Facing Application, T1496 Resource Hijacking, T1071.001 Web Protocols |
| **Severity** | High for inbound with inference API calls or more than 100 KB returned, otherwise Medium |
| **Runs** | Hourly over 1 hour |

## Goal
Find self-hosted AI servers that anyone on the internet can reach, before attackers find them. Also find internal hosts quietly using someone else's exposed server.

## Background
Ollama, LM Studio, text-generation-webui and ComfyUI take minutes to install, often end up on a GPU workstation or a forgotten VM, and have no authentication by default. Internet scans turn up thousands of exposed Ollama servers on port 11434. Attackers use them for free inference, as the brain for their own tools, or to pull, overwrite or poison models with `/api/pull`, `/api/create` and `/api/push`.

## How it works
1. Take FortiGate sessions that were allowed to an inference port (11434 Ollama, 1234 LM Studio, 7860 Gradio/TGWUI, 8188 ComfyUI), or to an inference API path when UTM web logging gives you the URL (`/api/generate|chat|tags|pull|push|create|embed|show|ps`, `/v1/chat/completions|completions|models|embeddings`).
2. **Inbound:** a public source reaching an internal host, or one of `ownedPublicRanges` for firewalls that log the public VIP before NAT. Grouped per internal host, with the number of different external sources, the paths used and the bytes the server sent back. A lot of bytes sent back means the server was actually used and the traffic wasn't just a scan.
3. **Outbound:** an internal host connecting to a public IP on an inference port. Paths alone don't count for outbound traffic, because `/v1/chat/completions` to OpenAI or Azure is normal SaaS use.

## Technical context
- Ports 1234 and 7860 are also used by other software. A matching path is stronger evidence, so path matches make the inbound alert High.
- FortiGate `ReceivedBytes` is what the source received. For inbound sessions that's what the server sent back.
- The path regex is tested: `/api/chat` matches, `/api/chatbot-config` and `/api/generated-reports` don't.

## Blind spots
- Servers on non-default ports without UTM URL logging.
- Servers published through a reverse proxy or a tunnel (ngrok, Cloudflare Tunnel) that skips the firewall. On the endpoint you can look for `DeviceNetworkEvents` listening on 11434, or `ollama serve` with `OLLAMA_HOST=0.0.0.0`.
- Inference servers in cloud VPCs or VNets that don't log to this FortiGate. Use the cloud flow logs for those.

## False positives
- Internal AI platforms that are meant to be published behind authentication. Add them to `approvedInferenceHosts`.
- Other services that happen to use ports 1234, 7860 or 8188. Check `Paths` and the host owner.

## Validation
- **Sample data:** `node tools/render-test.js exposed-llm-inference-server`. Expected result: 10.0.5.20 inbound High and 10.0.8.15 outbound Medium. The denied, SaaS and non-Fortinet rows don't show up.
- **Lab:** run `OLLAMA_HOST=0.0.0.0 ollama serve` behind a test VIP and request `/api/tags` from an outside host.

## Response
1. Block the port on the firewall, then find out who owns the internal host.
2. Assume other people have used the server. Check its logs for `/api/pull`, `/api/create` and `/api/push`. Models may have been replaced or poisoned, so don't trust them.
3. If the server is needed, publish it again behind authentication (a reverse proxy with SSO) on an approved host.
4. **Outbound:** find which process on the internal host talked to the external server (`DeviceNetworkEvents`). It's either someone's shadow-AI tool or malware using stolen compute.
