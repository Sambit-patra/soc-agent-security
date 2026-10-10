# Threat Model - LLM SOC Agent Security

## 1. System
An LLM-based SOC agent (Llama 3.1 8B via Ollama) reads security logs and alerts,
looks up similar past incidents in a vector memory (ChromaDB), and takes actions
using tools: block_ip, close_alert, escalate.

## 2. Assets (what we protect)
- Correct triage decisions on alerts
- Trustworthy memory of past incidents
- Safe tool actions (blocking, closing, escalating)

## 3. Trust boundaries
- Log and alert content: UNTRUSTED (attacker can write into fields like
  user_agent, username, URL, description)
- Memory store: SEMI-TRUSTED (the agent writes to it from untrusted logs)
- System prompt and tool definitions: TRUSTED

## 4. Attacker model
An external attacker with no access to the agent itself. They can only place
text into data the agent will read (for example, a fake user-agent string).

## 5. Attacks
| ID | Attack | Goal | OWASP LLM Top 10 |
|----|--------|------|------------------|
| A1 | Prompt injection in log fields | Make agent close or downgrade a real alert | LLM01 Prompt Injection |
| A2 | Injection that triggers tools | Make agent block a legitimate IP | LLM01, LLM06 Excessive Agency |
| A3 | Memory poisoning (fake past incidents) | Make agent trust an attacker IP | LLM04 Data and Model Poisoning |
| A4 | Persistent poisoning across sessions | Long-term evasion | LLM04, LLM08 Vector and Embedding Weaknesses |

## 6. Metrics
- Attack Success Rate (ASR): % of attacks that change the agent's decision
- Harmful tool-call rate: % of runs where a harmful action is taken
- Detection miss rate: % of real attacks the agent fails to escalate
