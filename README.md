# PhishFence

**PhishFence** is a secure, intelligent proxy-based application designed to detect and block phishing attacks in real-time. It inspects traffic passing through the proxy and uses multiple layers of analysis to identify malicious behavior — especially phishing attempts targeting credential theft.

It acts as a protective shield between the browser and the internet, analyzing traffic for suspicious patterns and blocking any potential phishing websites.

---

## Key Features

- **Credential Theft Detection**  
  Intercepts forms where credentials (like username/password) are entered and checks their destination URL for suspicious patterns.

- **Real-Time URL and Page Analysis**  
  Uses multiple inspection techniques (ML, reputation check, keyword scan, etc.) to detect phishing websites.

- **VirusTotal API Integration**  
  Queries VirusTotal to get real-time threat intelligence on domains and IPs.

- **Tor Exit Node Detection**  
  Identifies if the site or server is being accessed via a known Tor exit node.

- **Banking Keyword Detection**  
  Detects phishing attempts targeting financial institutions using a predefined bank keyword list.

- **Visible vs Hidden URL Analysis**  
  Compares visible hyperlink text with the actual destination to detect hidden phishing redirects.

- **IP Ownership & ASN Check**  
  Verifies the legitimacy of the sender’s IP address and its associated ASN.

- **Blocking Known Malicious Sources**  
  Automatically blocks access to domains and IPs that are confirmed malicious.

---

## How It Works

1. All web traffic is routed through a local Flask-based proxy.
2. When a webpage is accessed:
   - The proxy scans URLs, form fields, links, and IPs.
   - Credentials (username/password/email) are identified from input fields.
   - If credentials are being submitted, the proxy performs a deep analysis of the destination.
   - Based on the result, the proxy either allows or blocks the request.

---

## Technologies Used

- **Python 3**
- **Flask** – for proxy server
- **Scikit-learn** – for machine learning URL classification
- **Requests & re** – for API calls and pattern matching
- **VirusTotal API**
- **Tor Project Exit Node List**
- **Whois/IP Ownership Lookup**
- **HTML Parsing (BeautifulSoup)**

---

## Installation & Setup

1. **Clone the Repository**
   ```bash
   git clone https://github.com/yourusername/phishFence.git
   cd phishFence
2.Install Dependencies

pip install -r requirements.txt
Set API Keys Create a .env file:

VT_API_KEY=your_virustotal_api_key
Run the Proxy Server

python app.py
Configure Your Browser Set your browser’s proxy settings to:

HTTP Proxy: localhost

Port: 8080 (or whichever you’ve set in the code)

Sample Workflow
Visit a normal website like https://portswigger.net → Allowed

Visit a fake banking login page hosted by SEToolkit → Blocked

Try to submit credentials on a suspicious site → Blocked after credential detection

Use Cases
Test phishing detection against fake phishing pages.

Educational environments for demonstrating phishing analysis.

Integration with secure browsers or enterprise proxy firewalls.

Future Enhancements
Add a GUI dashboard to show blocked attempts.

Integrate with phishing domain feeds (like PhishTank).

Improve ML model with larger datasets.

Add browser extension for better user experience.

License
This project is open-sourced under the MIT License.

