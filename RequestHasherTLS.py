# program to hash request data and timestamp with private key and send it to downstream system
# python library for time and system
import time, sys
# python library to handle threads
import threading
# python library to handle socket connection
from socket import *
# python library for signing the hash and timestamp value
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256
# library to support TLS connection over sockets
import ssl
# library for base64 encoding
import base64


# getting the port number from the user through command line
# checking if the arguments in the command line has more than one parameter
if len(sys.argv) == 2:
    # expecting the input to be of the form python server.py <port number>
    server_port = int(sys.argv[1])
else:
    # default port of the server is 8080 if the user doesn't supply any parameters
    server_port = 8888
logger_file_name = "hashservice_log.txt"


class Server:
    # code ref:- http://www.geeksforgeeks.org/creating-a-proxy-webserver-in-python-set-1/
    # code ref:- http://luugiathuy.com/2011/03/simple-web-proxy-python/
    def __init__(self):
        try:
            self.server_socket = socket(AF_INET, SOCK_STREAM)  # Create a TCP socket
            # AF_inet = IPv4 and SOCK_STREAM = TCP
            self.server_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)  # Re-use the socket
        except error as e:
            print 'Unable to create/re-use the socket. Error: %s' % e
            message = 'Unable to create/re-use the socket. Error: %s' % e
            self.log_info(message)
        # bind the socket to a public/local host, and a port
        self.server_socket.bind(('', server_port))
        # allowing up to 200 client connections
        self.server_socket.listen(200)
        message = "Host Name: Localhost and Host address: 127.0.0.1 and Host port: " + str(server_port) + "\n"
        self.log_info(message)
        print "Server is ready to listen for clients at port "+str(server_port)

    def listen_to_client(self):
        """ waiting for client to connect over tcp to the proxy server"""
        while True:
            try:
                # accepting client connection
                client_connection_socket, client_address = self.server_socket.accept()
                # printing the relevant client details on the server side - logging purposes uncomment if needed
                '''
                client_details_log = "******************** Client Details:- ********************\n"
                client_details_log += "Client host name: " + str(client_address[0]) + "\nClient port number: " + str(
                    client_address[1]) + "\n"
                client_socket_details = getaddrinfo(str(client_address[0]), client_address[1])
                client_details_log += "Socket family: " + str(client_socket_details[0][0]) + "\n"
                client_details_log += "Socket type: " + str(client_socket_details[0][1]) + "\n"
                client_details_log += "Socket protocol: " + str(client_socket_details[0][2]) + "\n"
                client_details_log += "Timeout: " + str(client_connection_socket.gettimeout()) + "\n"
                client_details_log += "********************************************************\n"
                self.log_info(client_details_log)
                # Logging
                message = "Client IP address: " + str(client_address[0]) + " and Client port number: " \
                          + str(client_address[1]) + "\n"
                self.log_info(message)
                '''
            except KeyboardInterrupt:
                print "Server Stopped"
                break
            except error as e:
                print "Some error occurred "+str(e)
                break
            # creating a new thread for every client
            d = threading.Thread(name=str(client_address), target=self.proxy_thread,
                                 args=(client_connection_socket, client_address))
            d.setDaemon(True)
            d.start()

    def proxy_thread(self, client_connection_socket, client_address):
        """ method to create a new thread for every client connected """
        # getting the client request
        client_request = client_connection_socket.recv(1024)

        #  env
        apigw_host = "<value>.execute-api.us-east-1.amazonaws.com"
        apigw_port = 443

        # replacing the localhost hostname to the hostname which is being called
        client_request = str(client_request).replace('localhost:8888', apigw_host+":"+str(apigw_port))

        # if the request is not empty request i.e it contains some data
        if client_request:
            # get timestamp and hash the request and send it as a header in the response downstream
            split_data = str(client_request).split('\n\r\n')
            # getting the body part
            request_body = split_data[1]
        else:
            request_body = ""

        # getting current time stamp
        current_time = int(time.time())

        # introduced to demo old request being rejected
        # TODO remove the below line if deployed on production
        # time.sleep(6)

        # encoding the request body and time stamp with utf 8 to avoid compatibility issue using python 3
        hash_body = (request_body + str(current_time)).encode('utf-8')

        # hashing the generated hash body
        hash_obj = SHA256.new(hash_body)
        # string version of the hex digest
        hash_value = hash_obj.hexdigest()

        print hash_value

        # importing the private key
        f = open('mykey.pem', 'r')
        private_key = RSA.importKey(f.read())
        f.close()

        # getting signer as per PKCS1_PSS version
        signer = PKCS1_PSS.new(private_key)

        # encrypting the hash object
        signature = signer.sign(hash_obj)
        # base 64 encoding the signature for header payload
        sign_enc = base64.b64encode(signature)

        # generating the new request by appending the hash and timestamp as an header message with the request body
        new_request_data = split_data[0] + "\nSignature-Hash: "+str(current_time) + "," + str(sign_enc) + '\n\r\n' + request_body

        # connecting to the backend i.e. AWS API GW
        backend_connection_socket = socket(AF_INET, SOCK_STREAM)

        # enforcing TLSv1 as SSL protocol
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        # setting up server name indication
        backend_connection_socket_ssl = context.wrap_socket(backend_connection_socket, server_hostname=apigw_host)
        try:
            backend_connection_socket_ssl.settimeout(2)
            # connecting to the API Gateway
            backend_connection_socket_ssl.connect((apigw_host, apigw_port))
            # sending the modified data
            backend_connection_socket_ssl.send(new_request_data)
            web_server_response_append = ""
            # to get server response in loop until zero data or timeout of 2 seconds is reached
            #TODO to improve this logic on timeout
            timeout_flag = False
            while True:
                try:
                    web_server_response = backend_connection_socket_ssl.recv(4096)
                except timeout:
                    # a time out occurred on waiting for server response so break out of loop
                    if len(web_server_response_append) <= 0:
                        timeout_flag = True
                    break
                except ssl.SSLError:
                    # a time out occurred on waiting for server response so break out of loop
                    if len(web_server_response_append) <= 0:
                        timeout_flag = True
                    break
                if len(web_server_response) > 0:
                    web_server_response_append += web_server_response
                else:
                    # all the data has been received so break out of the loop
                    break

            if timeout_flag:
                # got bored waiting for response
                error_response = "HTTP/1.1 408 Request timeout\r\n\r\n"
                client_connection_socket.send(error_response)
            else:
                # sending the response back to client
                client_connection_socket.send(web_server_response_append)

        except error as e:
            client_connection_socket.send('HTTP/1.1 404 not found\r\n\r\n')
            message = "Client with port: " + str(client_address[1]) + " Following error occurred : " + str(e) + "\n"
            self.log_info(message)

        # closing the socket tls connection
        backend_connection_socket_ssl.close()

        # closing the client connection socket
        client_connection_socket.close()
        message = "Client with port: " + str(client_address[1]) + " connection closed \n"
        self.log_info(message)

    # logger function to write messages to log file in appending format
    def log_info(self, message):
        logger_file = open(logger_file_name, "a")
        logger_file.write(message)
        logger_file.close()

if __name__ == "__main__":
    # creating the instance of the server class
    server = Server()
    # calling the listen to Client call
    server.listen_to_client()