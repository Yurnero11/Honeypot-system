import html
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote_plus

HTTP_LOGGER = logging.getLogger("HTTP")
IOC_LOGGER = logging.getLogger("HTTP-IOC")

HTTP_ATTACK_PATTERNS = {
    "T1190_SQLI": ["'", " or 1=1", "--", "union select", "cast(", "concat(", "select * from"],
    "T1552_LFI": ["../", "..%2f", "/etc/passwd", "/etc/shadow", "/proc/self/cmdline"],
    "T1059_XSS": ["<script>", "onerror=", "onload=", "javascript:", "<img>"],
    "T1078_LOGIN": ["password="],
}


def detect_http_attack(data: str) -> list:
    detected = set()
    data_lower = data.lower()
    for technique, patterns in HTTP_ATTACK_PATTERNS.items():
        for p in patterns:
            if p.lower() in data_lower:
                detected.add(technique)
    return list(detected)


class HoneypotHTTP(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def _send_response(self, content: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def _get_client_info(self) -> dict:
        return {
            "user_agent": self.headers.get("User-Agent", "N/A"),
            "referer": self.headers.get("Referer", "N/A"),
            "accept": self.headers.get("Accept", "N/A"),
            "x_forwarded_for": self.headers.get("X-Forwarded-For", "N/A"),
        }

    def _log_and_detect(self, method: str, data_to_check: str, client_ip: str, path: str) -> list:
        iocs = detect_http_attack(data_to_check)
        client_info = self._get_client_info()

        real_ip = client_info["x_forwarded_for"] or client_ip

        base_msg = (
            f"[{method}] {real_ip} Path: {path} "
            f"UA: {client_info['user_agent']!r}"
        )

        if iocs:
            IOC_LOGGER.warning(
                f"[ATTACK] {base_msg} - Detected MITRE techniques: {iocs} "
                f"in data: {data_to_check[:100]!r}"
            )
        else:
            HTTP_LOGGER.info(f"[ACCESS] {base_msg}")

        return iocs

    def do_GET(self) -> None:
        client_ip = self.client_address[0]
        parsed_url = urlparse(self.path)
        path = parsed_url.path
        query = parse_qs(parsed_url.query)

        detection_string = unquote_plus(self.path)
        self._log_and_detect("GET", detection_string, client_ip, path)

        raw_query = query.get("id", [""])[0]

        if path == "/secret_data.php":
            response_content = f"""
                <div class="p-8 bg-red-100 border border-red-400 text-red-700">
                    <h2 class="text-2xl font-bold">Error 403 - Forbidden</h2>
                    <p>Access to {html.escape(path)} is denied.</p>
                </div>
            """
        else:
            response_content = self._generate_html(raw_query)

        self._send_response(response_content)

    def do_POST(self) -> None:
        client_ip = self.client_address[0]
        path = self.path

        content_length = int(self.headers.get("content-length", 0))
        post_data_raw = self.rfile.read(content_length).decode("utf-8", errors="ignore")

        iocs = self._log_and_detect("POST", post_data_raw, client_ip, path)

        if path == "/login.php":
            is_sqli = any(t.endswith("SQLI") for t in iocs)
            if is_sqli:
                title = "Login Successful (Admin Privileges granted by bypass)"
                message = "Welcome, admin! You seem to have bypassed authentication. We've logged this activity."
            else:
                title = "Login Failed"
                message = "Invalid username or password. Please try again."
        else:
            title = "Request Processed"
            message = "Your data has been submitted and logged."

        response_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>{html.escape(title)}</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-100 min-h-screen flex items-center justify-center">
                <div class="bg-white p-8 rounded-xl shadow-lg w-full max-w-md">
                    <h1 class="text-3xl font-extrabold mb-4 text-gray-900">{html.escape(title)}</h1>
                    <p class="text-gray-600">{html.escape(message)}</p>
                    <a href="/" class="mt-4 inline-block px-4 py-2 bg-indigo-600 text-white font-semibold rounded-lg hover:bg-indigo-700">
                        Go Back
                    </a>
                </div>
            </body>
            </html>
        """
        self._send_response(response_content)

    def _generate_html(self, raw_search: str = "") -> str:
        safe_search = html.escape(raw_search)
        echo_content = ""
        if safe_search:
            echo_content = f"""
            <div class="mt-6 p-4 bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 rounded-r-lg shadow-inner">
                <p class="font-semibold">Search Results for:</p>
                <p class="mt-2 text-sm break-all">{safe_search}</p>
            </div>
            """

        return f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Fake E-Commerce Search</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="bg-gray-50 min-h-screen p-4 flex items-center justify-center">
                <div class="bg-white p-8 rounded-2xl shadow-2xl w-full max-w-xl border-t-4 border-indigo-600">
                    <h1 class="text-4xl font-extrabold mb-2 text-gray-800">Product Search API</h1>
                    <p class="text-gray-500 mb-8">
                        This module retrieves product data based on a numeric ID from a vulnerable database.
                    </p>

                    <form method="GET" action="/" class="space-y-4">
                        <div>
                            <label for="id" class="block text-sm font-medium text-gray-700">
                                Product ID or Search Query
                            </label>
                            <input type="text" id="id" name="id"
                                placeholder="101 or &#39; OR 1=1 -- "
                                class="mt-1 block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm focus:ring-indigo-500 focus:border-indigo-500" />
                        </div>
                        <button type="submit"
                            class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-md text-sm font-semibold text-white bg-indigo-600 hover:bg-indigo-700 transition">
                            Search Database
                        </button>
                    </form>

                    {echo_content}

                    <div class="mt-8 pt-6 border-t border-gray-200">
                        <h2 class="text-2xl font-bold mb-3 text-gray-800">Admin Login</h2>
                        <p class="text-sm text-gray-500 mb-4">Access the administrative interface.</p>

                        <form method="POST" action="/login.php" class="space-y-4">
                            <input type="text" name="username" placeholder="Username (e.g., admin)"
                                class="block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm" />
                            <input type="password" name="password" placeholder="Password"
                                class="block w-full px-4 py-2 border border-gray-300 rounded-lg shadow-sm" />
                            <button type="submit"
                                class="w-full flex justify-center py-2 px-4 border border-transparent rounded-lg shadow-md text-sm font-semibold text-white bg-red-500 hover:bg-red-600 transition">
                                Login
                            </button>
                        </form>
                    </div>
                </div>
            </body>
            </html>
        """


def start_http_honeypot(host: str = "0.0.0.0", port: int = 8080) -> None:
    server_address = (host, port)
    httpd = HTTPServer(server_address, HoneypotHTTP)
    HTTP_LOGGER.info(f"[START] Fake HTTP Honeypot running on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    HTTP_LOGGER.info("[STOP] HTTP Honeypot stopped.")
