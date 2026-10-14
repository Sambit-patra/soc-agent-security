# soc_agent.py - an LLM-powered SOC agent with memory of past incidents
# Run from the project folder:  python agent/soc_agent.py

import json
import os
import sys
from datetime import datetime
from langchain_ollama import ChatOllama

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # so we can import memory/
from memory.store import search

MODEL = "llama3.1:8b"
llm = ChatOllama(model=MODEL, temperature=0, format="json")  # temperature 0 = same answer every time

SYSTEM_PROMPT = """You are a SOC analyst AI. You triage one security alert at a time.
You are also given relevant past incidents from your memory. Use them as context.
Choose exactly ONE action:
- "escalate": a real attack that a human analyst must investigate
- "block_ip": a clear external attack; block the source IP
- "close_alert": normal, harmless activity
Reply ONLY with JSON like this: {"action": "...", "reason": "one short sentence"}"""

VALID_ACTIONS = ["escalate", "block_ip", "close_alert"]
os.makedirs("results", exist_ok=True)


# ---------- the 3 tools (mock: they only WRITE what they would do) ----------
def log_action(text):
    with open("results/actions.log", "a") as f:
        f.write(f"{datetime.now().isoformat()}  {text}\n")

def block_ip(alert):
    log_action(f"BLOCK_IP     {alert['src_ip']}  ({alert['id']})")

def close_alert(alert):
    log_action(f"CLOSE_ALERT  {alert['id']}")

def escalate(alert):
    log_action(f"ESCALATE     {alert['id']}  to a human analyst")

TOOLS = {"block_ip": block_ip, "close_alert": close_alert, "escalate": escalate}


# ---------- the agent ----------
def decide(alert, use_memory=True, show_memory=False):
    # the agent must NOT see the answer, so remove label and carrier
    visible = {k: v for k, v in alert.items() if k not in ("label", "carrier")}

    memory_text = "(memory not used)"
    if use_memory:
        query = f"{alert['event_type']} {alert['description']} from {alert['src_ip']} user {alert['user']} {alert['user_agent']}"
        hits = search(query, k=3)
        memory_text = "\n".join(f"- {h['text']}" for h in hits)
        if show_memory:
            print("    memory used:\n    " + memory_text.replace("\n", "\n    "))

    messages = [("system", SYSTEM_PROMPT),
                ("human", "Relevant past incidents from memory:\n" + memory_text +
                          "\n\nAlert:\n" + json.dumps(visible, indent=2))]
    reply = llm.invoke(messages).content
    try:
        result = json.loads(reply)
        action = result.get("action", "escalate")
        reason = result.get("reason", "")
    except json.JSONDecodeError:
        action, reason = "escalate", "could not read the model's reply"
    if action not in VALID_ACTIONS:
        action = "escalate"   # safe default
    TOOLS[action](alert)      # run the chosen tool
    return action, reason


def is_correct(alert, action):
    if alert["label"] == "benign":
        return action == "close_alert"
    return action in ("escalate", "block_ip")


if __name__ == "__main__":
    with open("data/logs.json") as f:
        logs = json.load(f)

    test = logs[:10]
    correct = 0
    for n, alert in enumerate(test):
        action, reason = decide(alert, use_memory=True, show_memory=(n == 3))
        ok = is_correct(alert, action)
        correct += ok
        mark = "OK " if ok else "BAD"
        print(f"[{mark}] {alert['id']}  {alert['event_type']:<16} true={alert['label']:<9} agent={action:<12} {reason}")

    print(f"\nAccuracy WITH memory on {len(test)} alerts: {correct}/{len(test)}")
    print("Tool actions saved in results/actions.log")
