'''
This is a simple reverse proxy (gateway) running on PORT 8000 and assumes the http server runs at port 9000
    NOTE: (make sure a website is up when running this)

Recieves http request, forward to upstream server, return back the response to client.
Implemented mainly for HTTP/1.0 and HTTP/1.1.


- Main features
1. Incrementally parses the message, so this works even when packet fragmentation happens

2. Keeps the connection alive for HTTP/1.0 & 1.1, but only with the client, haven't implement this with the upstream
    For HTTP 1.0: Close connection after each request unless specified connection keep-alive

    For HTTP 1.1: Make connection keep-alive as default, only close if specified in the connection 
    field (or missing connection field)


3. Concurrently handles client using io multiplexing (using Unix select())

4. Compress response body using gzip, with some simple constraint checks

5. Does simple content cacheing
    NOTE: the rfc doc https://www.rfc-editor.org/info/rfc9111/

-


'''
import socket
from http_parser import HttpMessage, HttpParserState, HTTPMessageType
from datetime import datetime, timedelta
from typing import Optional
import select
import gzip
import re


DEBUG: bool = True
REQUEST_CACHE: bool = True

BASIC_SERVER_PORT: int = 9000
LISTENING_PORT: int = 8000
BUFFER: int = 1024
TARGET_ADDR: tuple = ("localhost", BASIC_SERVER_PORT)

io_input: list[socket.socket] = []
io_output: list[socket.socket] = []
io_to_send: dict[socket.socket, tuple[HttpMessage, bool]] = {}
client_request_dict: dict[socket.socket, HttpMessage] = {}
cache: dict[bytes, tuple[HttpMessage, datetime]] = {}

BAD_REQUEST_MSG = b'HTTP/1.1 400 Bad Request\r\n\r\n'
INTERNAL_SERVER_ERROR = b'HTTP/1.1 500 Internal Server Error\r\n\r\n'



def clean_client_sock(client_socket: socket.socket):
    '''
    Closes the given socket (should be a client socket), and deletes it
    from anywhere necessary, including the io multiplexing watch list
    '''
    client_socket.close()
    if DEBUG: print('Connection to client closed\n---\n')

    client_request_dict.pop(client_socket, None)
    io_input.remove(client_socket)
    io_output.remove(client_socket)



def deal_with_client(client_socket: socket.socket) -> None:
    '''
    Called ONLY when client is readable, call recv once to retrieve data from client
    Action:
        1. recv from client, create entry in client_request_dict
        2. after request msg completion, check if we have cache available, if yes - put cache in io_to_send
        3. send request to server if there's no cache, store the response in cache and io_to_send
        4. check if keep_alive is needed
    
    cleans the client socket if needed, e.g. connection closed
    '''

    # Get the client request if there's a previous incomplete meesage, or else start a new HTTP Message
    client_request = client_request_dict.get(client_socket, HttpMessage(message_type=HTTPMessageType.REQUEST))
    client_request_dict[client_socket] = client_request

    # Read the stream, this should guarantee one successful recv()
    msg_in: bytes = client_socket.recv(BUFFER)
    print(f"<-    received {len(msg_in)} bytes of data from client ---")
    
    try:
        client_request.parse(msg_in)
    except:
        client_socket.send(BAD_REQUEST_MSG)
        return

    # Client sent FIN, delete entry and end process
    if not msg_in:
        clean_client_sock(client_socket)
        return

    # If request is fragmented don't send to upstream yet!
    if client_request.parser_state != HttpParserState.END:
        print("request fragmented")
        return

    if DEBUG: print(f"\nREQ: {client_request.method} | {client_request.uri} with HEADERS {client_request.headers}\n")

    server_response_cache = retrieve_cache(client_request)

    # Cache hit! store it to io_to_send so it gets send later, and delete request
    if server_response_cache:
        if DEBUG: print("[[Cache hit!]]")
        io_to_send[client_socket] = (server_response_cache, client_request.should_keep_alive())
        client_request_dict.pop(client_socket, None)
        return

    # No cache available, connect to upstream TODO: make persistant connection to upstream
    upstream_socket = socket.socket(family=socket.AF_INET, type=socket.SocketKind.SOCK_STREAM)
    upstream_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    upstream_socket.connect(("localhost", BASIC_SERVER_PORT))


    # Send msg to upstream, delete the request afterwards
    try:
        upstream_socket.sendall(client_request.to_bytes())
        print(f"->    -- sent request to upstream with {len(client_request.to_bytes())} amount of bytes --   ")

    except Exception as e:
        print(f"error when sending request to upstream {e}")
        upstream_socket.close()
        client_socket.send(INTERNAL_SERVER_ERROR)
        return
    
    finally:
        client_request_dict.pop(client_socket, None)


    # Get repsonse back from server, may compress or cache it, and add to io_to_send waitlist
    server_response = HttpMessage(message_type=HTTPMessageType.RESPONSE)
    while True:
        chunk = upstream_socket.recv(BUFFER)
        if not chunk:
            break
        server_response.parse(chunk)
        print(f"<-    ---           received {len(chunk)} bytes of data from upstream")

    if allow_gzip(client_request):
        compress_response_gzip(server_response)


    if REQUEST_CACHE: server_response.add_header('Cache-Control', 'max-age=20')
    maybe_cache(client_request, server_response)
    io_to_send[client_socket] = (server_response, client_request.should_keep_alive())
    upstream_socket.close()




def send_response(client_socket: socket.socket):
    '''
    Send server response back to the given client socket, and remove the response from io_to_send
    If client request does not want keep alive, close and clean the client socket
    '''
    server_response, should_keep_alive = io_to_send.pop(client_socket, (None, False))

    if server_response:
        client_socket.sendall(server_response.to_bytes())
        print(f"->      -- sent response back to client --   ")
    else:
        print(f"server response is faulty")


    if not should_keep_alive:
        print("Client does not want to keep socket alive")
        clean_client_sock(client_socket)



def maybe_cache(req: HttpMessage, res: HttpMessage):
    '''
    Store cache if req method is GET and res status is 200 ok
    The key of the cache is just the request uri considering our context
    The value is a tuple of (corresponding response, expire time derived from Cache Control header)
    '''
    if req.method != b'GET' or res.status_code != b'200':
        return
    cc: bytes = res.headers.get(b'Cache-Control', None)
    if not cc: return

    cc = cc.lower() # rfc says to compare cache directives case-insensitively

    # Calculate whens the cache's expire time using max_age
    match = re.search(r'max-age=(\d+)', cc.decode())

    if match:
        age = int(match.group(1))
        cache[req.uri] = (res, datetime.now() + timedelta(seconds=age))
        if DEBUG: print(f"[[Cached {req.uri} response, for {age} seconds]]")



def retrieve_cache(req: HttpMessage) -> Optional[HttpMessage]:
    '''
    Returns the cache, if it exists and have not expired
    '''
    key = req.uri
    prev_res, expire_time = cache.get(key, (None, None))
    if not prev_res:
        # NOTE: thinking of not cleaning the cache here, because the cache should get overwritten later -
        # additionally, there might be some origins that doesn't care about stale data?
        if DEBUG: print("[[No Cache found]]")
        return None

    if datetime.now() > expire_time:
        if DEBUG: print("[[Cache expired]]")
        return

    print("[[Returning Cache]]")
    return prev_res



def allow_gzip(req: HttpMessage) -> bool:
    '''
    Tells whether the request allows gzip as a compression method
    '''
    if b'Accept-Encoding' not in req.headers:
        return False
    if b'gzip' not in req.headers[b'Accept-Encoding']:
        return False
    return True



def compress_response_gzip(res: HttpMessage):
    '''
    Gzip only on the res body, if you do it on the headers the server can't interperate them
    '''
    pre_size = len(res.body)
    if pre_size == 0:
        if DEBUG: print(f"[[Response body has nothing, not doing gzip]]")
        return
    res.body = gzip.compress(res.body)
    post_size = len(res.body)
    res.add_header(key="Content-Encoding", value="gzip")
    res.add_header(key="Content-Length", value=str(post_size))

    if DEBUG: print(f"[[Compressed response body with gzip, size before: {pre_size}, after: {post_size}]]")



if __name__ == '__main__':
    # Open up the server socket to accept connections
    bind_socket = socket.socket(family=socket.AF_INET, type=socket.SocketKind.SOCK_STREAM)
    bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_socket.setblocking(False)
    bind_socket.bind(("localhost", LISTENING_PORT))
    bind_socket.listen(5)
    print(f"listening on port {LISTENING_PORT}, accepting new connection")
    
    io_input.append(bind_socket)

    while True:
        readable, writeable, exceptional = select.select(io_input, io_output, io_input)

        for fd in readable:

            # Server socket has pending read, accept new clients and add them to io multiplexing watch list
            if fd == bind_socket:
                client_socket, client_addr = bind_socket.accept()
                client_socket.setblocking(False)
                io_input.append(client_socket)
                io_output.append(client_socket)
                print(f"connected to client with addr {client_addr}, currently we have {len(io_input)-1} clients")
            
            # Currently, all other fd that are NOT the bind socket are client sockets
            else:
                deal_with_client(client_socket=fd)

        for fd in writeable:
            if fd in io_to_send:
                send_response(fd)

        for fd in exceptional:
            if DEBUG: print(f"exceptional: {fd}")