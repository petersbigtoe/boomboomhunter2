from flask import Flask, request, jsonify, render_template_string, make_response
from datetime import datetime
from hashlib import sha256

app = Flask(__name__)

FLAG = "flag{hackera_boomboomhunter}"

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Header Hunter 2.0</title>
</head>
<body>
<h1>Header Hunter 2.0</h1>
<p>Fill the headers and submit to get the flag.</p>

<form id="headerForm">
  <label>X-Auth-Token: <input type="text" id="token" value="abc12346" /></label><br/><br/>
  <label>User-Agent: <input type="text" id="useragent" value="HeaderHunter/1.0" /></label><br/><br/>
  <label>X-Request-Signature: <input type="text" id="signature" placeholder="Generate below or type" /></label>
  <button type="button" onclick="generateSignature()">Generate Signature for Today</button><br/><br/>
  <button type="submit">Submit</button>
</form>

<pre id="result"></pre>

<script>
// Helper: SHA256 using Web Crypto API
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function getTodayYYYYMMDD() {
  const today = new Date();
  const yyyy = today.getFullYear();
  const mm = String(today.getMonth() + 1).padStart(2, '0');
  const dd = String(today.getDate()).padStart(2, '0');
  return `${yyyy}${mm}${dd}`;
}

async function generateSignature() {
  const dateStr = getTodayYYYYMMDD();
  const sig = await sha256(dateStr);
  document.getElementById('signature').value = sig;
}

document.getElementById('headerForm').onsubmit = async (e) => {
  e.preventDefault();
  const token = document.getElementById('token').value.trim();
  const ua = document.getElementById('useragent').value.trim();
  const signature = document.getElementById('signature').value.trim();
  const result = document.getElementById('result');
  result.textContent = 'Sending request...';

  try {
    const response = await fetch('/api/validate', {
      method: 'POST',
      headers: {
        'X-Auth-Token': token,
        'X-Request-Signature': signature,
        'User-Agent': ua,
      }
    });

    if (response.status === 200) {
      // Flag is sent in header 'X-Flag'
      const flag = response.headers.get('X-Flag') || 'No flag returned';
      result.textContent = `🎉 Success! Flag: ${flag}`;
    } else if (response.status === 403) {
      const data = await response.json();
      result.textContent = `⛔ Access Denied: ${data.message}`;
    } else {
      result.textContent = `Error: HTTP status ${response.status}`;
    }
  } catch (err) {
    result.textContent = `Request failed: ${err.message}`;
  }
};
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

@app.route('/api/validate', methods=['POST'])
def validate():
    token = request.headers.get('X-Auth-Token')
    signature = request.headers.get('X-Request-Signature')
    ua = request.headers.get('User-Agent')

    # Validate token
    if token != "abc12346":
        return jsonify({"message": "Invalid X-Auth-Token"}), 403

    # Validate User-Agent
    if ua != "HeaderHunter/1.0":
        return jsonify({"message": "Invalid User-Agent"}), 403

    # Validate signature (must be SHA256 hash of today's date YYYYMMDD)
    today_str = datetime.utcnow().strftime("%Y%m%d")
    expected_sig = sha256(today_str.encode()).hexdigest()

    if signature != expected_sig:
        return jsonify({"message": "Invalid X-Request-Signature"}), 403

    # Success: return flag in header
    resp = make_response(jsonify({"message": "Access granted"}), 200)
    resp.headers['X-Flag'] = FLAG
    return resp

if __name__ == '__main__':
    app.run(debug=True)
