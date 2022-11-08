from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import requests, time

host = "localhost"
port = 1234

class server(BaseHTTPRequestHandler):
    def do_GET(self):

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        content = open("main.html", "rb")
        self.wfile.write(content.read())

    def do_POST(self):
        if self.path == "/send":
            length = int(self.headers['Content-Length'])
            post_data = urllib.parse.parse_qs(self.rfile.read(length).decode('utf-8'))
                
            payload = post_data["payload"][0]
            send_payload(payload, self)

def send_payload(payload, self):
    print(payload)

    url = "http://127.0.0.1:80/send" # TODO get IP
    obj = {"0": payload}
    #r = requests.post(url, json=obj)
    #print(r)

    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.end_headers()
    content = open("confirmation.html", "rb")
    self.wfile.write(content.read())


if __name__ == "__main__":
    serv = HTTPServer((host, port), server)

    try:
        serv.serve_forever()
    except KeyboardInterrupt:
        pass

    serv.server_close()
