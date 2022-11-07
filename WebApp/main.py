from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import requests, time

host = "localhost"
port = 1234

class server(BaseHTTPRequestHandler):
    def do_GET(self):
        content = """<form action="/send" method="POST">
        <label for="payload">Please enter your payload</label><br>
        <input type="text" id="payload" name="payload"></input><br>
        <input type="submit" value="Send!">
        </form>
        """

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes("<html><head><title>:)</title></head>", "utf-8"))
        self.wfile.write(bytes(content, "utf-8"))
        self.wfile.write(bytes("</html>", "utf-8"))

    def do_POST(self):
        if self.path == "/send":
            length = int(self.headers['Content-Length'])
            post_data = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))
                
            payload = post_data["payload"][0]
            send_payload(payload, self)

def send_payload(payload, self):
    print(payload)

    url = "http://:80/send" # TODO get IP
    obj = {"0": payload}
    r = requests.post(url, json=obj)
    print(r)

    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    self.wfile.write(bytes("<html><head><title>:)</title></head>", "utf-8"))
    self.wfile.write(bytes("<p>Payload sent! Check for it on the other end in a few minutes.</p>", "utf-8"))
    self.wfile.write(bytes("<button onclick=\"window.location.href='/';\">Click here to send another message</button>", "utf-8"))
    self.wfile.write(bytes("</html>", "utf-8"))


if __name__ == "__main__":
    serv = HTTPServer((host, port), server)

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        pass

    serv.server_close()
