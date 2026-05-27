import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini")

if LLM_PROVIDER == "gemini":
    from langchain_google_genai import ChatGoogleGenerativeAI
    llm = ChatGoogleGenerativeAI(
        model=os.getenv("GEMINI_MODEL", "gemini-1.5-flash"),
        google_api_key=os.getenv("GOOGLE_API_KEY"),
        temperature=0.1
    )
elif LLM_PROVIDER == "anthropic":
    from langchain_anthropic import ChatAnthropic
    llm = ChatAnthropic(
        model=os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022"),
        anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
        temperature=0.1
    )
else:
    raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER}")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "default_secret")
CRITICAL_SCORE_THRESHOLD = int(os.getenv("CRITICAL_SCORE_THRESHOLD", 7))
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", 9))
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"