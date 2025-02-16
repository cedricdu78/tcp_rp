#!/usr/bin/env python

import sys
import socket
import threading

from http.server import BaseHTTPRequestHandler
from http.client import HTTPResponse
from http import HTTPStatus
from io import BytesIO

import traceback

import yaml

class ResponseWrapper():
    def __init__(self, response_bytes):
        self._file = BytesIO(response_bytes)

    def makefile(self, *args, **kwargs):
        return self._file

    def show_info(data):
        print("\nFROM server")
        print("status: %s" % data.status)
        print("")

class HTTPRequest(BaseHTTPRequestHandler):
    http_methods = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH']

    def __init__(self, data):
        self.rfile = BytesIO(data)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_is_possible()

    def send_error(self, code, message=None, explain=None):
        self.error_code = code
        self.error_message = message
        self.error_explain = explain

    def parse_is_possible(self):
        if self.raw_requestline.split(b' ')[0] in self.http_methods \
                and self.raw_requestline.split(b' ')[2].startswith(b'HTTP/'):
            self.parse_request()
            self.show_info()

    def show_info(self):
        print("\nFROM client")
        print("METHOD: %s" % self.requestline)
        print("CLOSE_CONNECTION: %s" % self.close_connection)
        if hasattr(self, 'headers'):
            print("HEADERS:")
            for key, value in self.headers.items():
                print(key, value)
        print("")

def handle_data(socket, exited):
    data = b''

    while True:
        chunk = None
        try: chunk = socket.recv(4096)
        except: break
        if chunk is None: break
        if chunk == b'':
            exited = True
            break
        data += chunk

    return data, exited

def create_socket(target):
    target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target_socket.connect((target['server'], target['port']))
    target_socket.setblocking(False)
    return target_socket

def handle_client(client_socket):
    try:

        client_socket.setblocking(False)
        target_socket = None

        exited = False

        while not exited and not programExited:

            request, exited = handle_data(client_socket, exited)
            if len(request):
                result = HTTPRequest(request)

                if target_socket is None:
                    if hasattr(result, 'headers'):
                        target_socket = create_socket(config[result.headers['host']])
                    else: break

                target_socket.send(request)

            response, exited = handle_data(target_socket, exited)
            if len(response):
                # result = HTTPResponse(ResponseWrapper(response))
                # result.begin()
                # ResponseWrapper.show_info(result)
                client_socket.send(response)

    except Exception as e:
        print(f"Erreur: {e}")
        traceback.print_exc()
    finally:
        print("Close connection")
        client_socket.close()
        if not target_socket is None:
            target_socket.close()

if __name__ == "__main__":

    localHost = sys.argv[1]
    localPort = int(sys.argv[2])

    config = yaml.safe_load(open('config.yaml'))['config']
    programExited = False

    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serverSocket.bind((localHost, localPort))
    serverSocket.listen(5)

    print("[*] Serveur en écoute...")

    while True:

        try:
            client_socket, address = serverSocket.accept()
        except:
            print("\nTerminating...")
            programExited = True
            break

        print(f"\n[*] Connexion reçue de {address}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

    serverSocket.close()
