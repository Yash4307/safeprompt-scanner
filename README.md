# SafePrompt Scanner - Prompt Injection Defender

A web-based tool to detect prompt injection attacks in text and webpages before feeding them to any LLM.

### Features
- Real-time prompt injection detection (strong, mild patterns + invisible/hidden characters)
- Webpage URL fetching with smart text cleaning
- Safe summarization using Groq (only when risk is Low)
- Detection of zero-width spaces and hidden Unicode characters
- Quick test prompts (Safe / Mild / Harmful)
- Scan history with statistics panel
- Export scan results as TXT
- Cyberpunk UI with Matrix rain background
- Timestamps shown in user's local timezone

### Tech Stack
- **Backend**: Flask + Python
- **Detection**: Custom regex + invisible character detection
- **Summarization**: Groq API
- **Frontend**: Bootstrap + Matrix rain canvas

### Local Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/Yash4307/safeprompt-scanner.git
   cd safeprompt-scanner
   
2. Create and activate virtual environment:
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
# source venv/bin/activate

3. Install dependencies:
pip install -r requirements.txt

4. Get your Groq API Key (Required for Safe Summarization):
Go to https://console.groq.com/keys
Sign up / Log in
Click "Create API Key"
Copy the key
Create a .env file in the project root and add:
GROQ_API_KEY=your_actual_key_here

5. Run the application:
python app.py

6. Open your browser and go to: http://127.0.0.1:5000

Note: Without a Groq API key, the "Scan + Safe Summarize" feature will not work (but detection will still function normally).

Live Demo - https://safeprompt-scanner.onrender.com

Made as an Educational ProjectDemonstrating practical AI security, prompt injection defense, and safe LLM usage.



