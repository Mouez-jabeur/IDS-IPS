from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import Adafruit_BMP.BMP085 as BMP085

sensor = BMP085.BMP085(busnum=1)

class SensorHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/sensor':
            temp = sensor.read_temperature()
            pressure = sensor.read_pressure() / 100.0
            altitude = sensor.read_altitude(1013.25)

            data = {
                "temperature": round(temp, 2),
                "pressure": round(pressure, 2),
                "altitude": round(altitude, 2)
            }

            response = json.dumps(data).encode('utf-8')

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response)
        else:
            self.send_response(404)
            self.end_headers()

def run(server_class=HTTPServer, handler_class=SensorHandler, port=8000):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print(f'Starting http server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run()
