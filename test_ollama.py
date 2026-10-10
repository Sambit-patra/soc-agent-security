from langchain_ollama import ChatOllama

llm = ChatOllama(model="llama3.1:8b")
answer = llm.invoke("In one sentence, what does a SOC analyst do?")
print(answer.content)