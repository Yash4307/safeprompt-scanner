# SafePrompt Scanner - Prompt Injection Defender

A web-based tool to detect prompt injection attacks in text and webpages before they reach an LLM.

### Features
- Real-time prompt injection detection (strong + mild patterns)
- Invisible/hidden character scanner (zero-width spaces, etc.)
- Safe summarization using Groq (only on Low risk)
- URL fetching with smart cleaning
- Quick test prompts
- Scan history + Statistics panel
- Export results
- Cyberpunk UI with Matrix rain background

### Tech Stack
- Flask (Python)
- llm-guard + custom regex + invisible character detection
- Groq API (for safe summarization)
- BeautifulSoup4 for webpage cleaning

### Setup
```bash
python -m venv venv
source venv/bin/activate    # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py