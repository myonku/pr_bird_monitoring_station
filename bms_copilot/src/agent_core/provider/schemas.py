import os
from openai import OpenAI

# Example usage of the DeepSeek API

client = OpenAI(
    api_key=os.environ.get("sk-ef96483db18e4cad96e7579d849d023c"),
    base_url="https://api.deepseek.com",
)

response = client.chat.completions.create(
    model="deepseek-v4-pro",
    messages=[
        {"role": "system", "content": "You are a helpful assistant"},
        {"role": "user", "content": "Hello"},
    ],
    stream=False,
    reasoning_effort="high",
    extra_body={"thinking": {"type": "enabled"}},
    response_format={"type": "json_object"},
)

print(response.choices[0].message.content)
