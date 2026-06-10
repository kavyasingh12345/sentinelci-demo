import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq")
print(f"[Config] LLM_PROVIDER: {LLM_PROVIDER}")
print(f"[Config] GROQ_API_KEY set: {bool(os.getenv('GROQ_API_KEY'))}")
print(f"[Config] GITHUB_TOKEN set: {bool(os.getenv('GITHUB_TOKEN'))}")
print(f"[Config] WEBHOOK_SECRET: {os.getenv('WEBHOOK_SECRET')}")

try:
    if LLM_PROVIDER == "gemini":
        from langchain_google_genai import ChatGoogleGenerativeAI
        llm = ChatGoogleGenerativeAI(
            model=os.getenv("GEMINI_MODEL", "gemini-2.0-flash"),
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
    elif LLM_PROVIDER == "groq":
        from langchain_groq import ChatGroq
        llm = ChatGroq(
            model="llama-3.3-70b-versatile",
            groq_api_key=os.getenv("GROQ_API_KEY"),
            temperature=0.1
        )
    else:
        raise ValueError(f"Unknown LLM_PROVIDER: {LLM_PROVIDER}")
    print(f"[Config] LLM initialized successfully")
except Exception as e:
    print(f"[Config] LLM initialization ERROR: {e}")
    llm = None

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "default_secret")
CRITICAL_SCORE_THRESHOLD = int(os.getenv("CRITICAL_SCORE_THRESHOLD", 7))
AUTO_BLOCK_THRESHOLD = int(os.getenv("AUTO_BLOCK_THRESHOLD", 9))
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"