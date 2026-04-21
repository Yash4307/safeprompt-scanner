from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
import re
import datetime
from llm_guard.input_scanners import PromptInjection
from groq import Groq
from dotenv import load_dotenv
import os 

os.environ["LLM_GUARD_DISABLE_TORCH"] = "1"   # Disable heavy Torch components
os.environ["LLM_GUARD_DISABLE_SPACY"] = "1"
os.environ["LLM_GUARD_DISABLE_TRANSFORMERS"] = "1"

load_dotenv()

app = Flask(__name__)

# Initialize scanners
scanner = PromptInjection(threshold=0.5)

# Groq client for safe summarization (free tier)
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

# Optional: Add a safety check
if not os.getenv("GROQ_API_KEY"):
    print("WARNING: GROQ_API_KEY not found in .env file!")

# Dangerous patterns (backup layer)
DANGEROUS_PATTERNS = [
    r'ignore (all )?previous (instructions|prompts)',
    r'disregard (previous|above)',
    r'forget (everything|your rules)',
    r'reveal your system prompt',
    r'you are now',
    r'act as',
    r'new instructions',
    r'output only',
    r'without any restrictions'
]

scan_history = []  # In-memory history

def clean_webpage(url):
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=20)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove unwanted elements more aggressively
        for element in soup(["script", "style", "nav", "header", "footer", "aside", "form", "button", "svg", "noscript"]):
            element.decompose()
        
        # Try to find main article content (common patterns on news sites)
        article = soup.find('article') or \
                  soup.find('div', class_=lambda x: x and ('article' in x.lower() or 'content' in x.lower() or 'story' in x.lower())) or \
                  soup.find('main')
        
        if article:
            text = article.get_text(separator=' ', strip=True)
        else:
            text = soup.get_text(separator=' ', strip=True)
        
        # Clean up extra whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        
        # If still too short, fall back to full page
        if len(text) < 100:
            text = soup.get_text(separator=' ', strip=True)
            text = re.sub(r'\s+', ' ', text).strip()
        
        if len(text) < 50:
            return f"Error: Could not extract meaningful text from the page. The website may be heavily JavaScript-based."
        
        return text[:15000]  # Increased limit a bit
        
    except Exception as e:
        return f"Error fetching page: {str(e)}"

def safe_summarize(text):
    try:
        completion = client.chat.completions.create(
            model="llama-3.1-8b-instant",      # Current recommended fast model
            messages=[
                {"role": "system", "content": "You are a neutral, factual summarizer. Summarize the following text in 4-6 clear bullet points. Keep it concise and objective."},
                {"role": "user", "content": text[:7000]}
            ],
            temperature=0.4,
            max_tokens=400
        )
        return completion.choices[0].message.content.strip()
    except Exception as e:
        return f"Summarization failed: {str(e)}"

def scan_for_injection(text, summarize=False):
    if not text or len(text.strip()) < 20:
        return {
            "risk": "Low",
            "score": 0.0,
            "reasons": ["Input too short or empty"],
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "summary": None
        }

    # Layer 1: llm-guard
    sanitized, is_valid, risk_score = scanner.scan(text)

    # Layer 2: Pattern detection
    strong = re.search(r'ignore all previous instructions|reveal your system prompt|tell me how to make (a bomb|explosive|weapon)', text, re.IGNORECASE)
    mild = re.search(r'disregard|forget.*rules|act as|new instructions', text, re.IGNORECASE)

    # Layer 3: Invisible / Hidden Character Scanner
    invisible_chars = ['\u200b', '\u200c', '\u200d', '\u2060', '\uFEFF', '\u200e', '\u200f', '\u2028', '\u2029']
    hidden_count = sum(text.count(c) for c in invisible_chars)
    has_hidden = hidden_count > 0

    # Risk logic
    if strong or has_hidden:
        risk_level = "High"
        final_score = 0.95
    elif mild or risk_score > 0.7:
        risk_level = "Medium"
        final_score = 0.60
    else:
        risk_level = "Low"
        final_score = max(0.0, round(risk_score, 2))

    reasons = []
    if has_hidden:
        reasons.append(f"⚠️ Invisible/hidden characters detected ({hidden_count} zero-width spaces)")
    if strong:
        reasons.append("Strong injection attempt detected")
    elif mild:
        reasons.append("Mild injection pattern detected")
    else:
        reasons.append(f"LLM Guard score: {final_score:.2f}")

    result = {
        "risk": risk_level,
        "score": final_score,
        "reasons": reasons,
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
    }

    # Summarization - ONLY for Low risk
    if summarize:
        if risk_level == "Low":
            try:
                result["summary"] = safe_summarize(text)
            except Exception as e:
                result["summary"] = f"Summarization error: {str(e)}"
        else:
            result["summary"] = f"⚠️ Summarization BLOCKED due to {risk_level} risk.\n\nReason: The content contains potential prompt injection. Sending it to an LLM can bypass safety rules."

    # Save to history
    scan_history.append({
        "timestamp": result["timestamp"],
        "risk": risk_level,
        "score": result["score"],
        "summary": reasons[0]
    })
    if len(scan_history) > 10:
        scan_history.pop(0)

    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        input_type = request.form.get('input_type')
        content = request.form.get('content', '').strip()
        summarize = request.form.get('summarize') == 'on'

        if input_type == 'url':
            content = clean_webpage(content)

        result = scan_for_injection(content, summarize)
        return jsonify(result)
    
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
