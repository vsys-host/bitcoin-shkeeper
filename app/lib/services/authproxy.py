try:
    import http.client as httplib
except ImportError:
    import httplib
import base64
import decimal
import json
import logging
import urllib.parse as urlparse

USER_AGENT = "AuthServiceProxy/0.1"

HTTP_TIMEOUT = 10

log = logging.getLogger(__name__)


class JSONRPCException(Exception):
    def __init__(self, rpc_error):
        parent_args = []
        try:
            parent_args.append(rpc_error['message'])
        except Exception:
            pass
        Exception.__init__(self, *parent_args)
        self.error = rpc_error
        self.code = rpc_error['code'] if 'code' in rpc_error else None
        self.message = rpc_error['message'] if 'message' in rpc_error else None

    def __str__(self):
        return '%d: %s' % (self.code, self.message)

    def __repr__(self):
        return '<%s \'%s\'>' % (self.__class__.__name__, self)


def EncodeDecimal(o):
    if isinstance(o, decimal.Decimal):
        try:
            return float(round(o, 8))
        except decimal.DecimalException as e:
            return float(o)
    raise TypeError(repr(o) + " is not JSON serializable")


class AuthServiceProxy(object):
    __id_count = 0

    def __init__(self, service_url, service_name=None, timeout=HTTP_TIMEOUT, connection=None):
        self.__service_url = service_url
        self.__service_name = service_name
        self.__url = urlparse.urlparse(service_url)
        if self.__url.port is None:
            port = 443 if self.__url.scheme == 'https' else 80
        else:
            port = self.__url.port
        (user, passwd) = (self.__url.username, self.__url.password)
        try:
            user = user.encode('utf8')
        except AttributeError:
            pass
        try:
            passwd = passwd.encode('utf8')
        except AttributeError:
            pass
        if not (user is None or passwd is None):
            authpair = user + b':' + passwd
            self.__auth_header = b'Basic ' + base64.b64encode(authpair)

        self.__timeout = timeout

        if connection:
            # Callables re-use the connection of the original proxy
            self.__conn = connection
        elif self.__url.scheme == 'https':
            self.__conn = httplib.HTTPSConnection(self.__url.hostname, port,
                                                  timeout=timeout)
        else:
            self.__conn = httplib.HTTPConnection(self.__url.hostname, port,
                                                 timeout=timeout)

    def __getattr__(self, name):
        if name.startswith('__') and name.endswith('__'):
            # Python internal stuff
            raise AttributeError
        if self.__service_name is not None:
            name = "%s.%s" % (self.__service_name, name)
        return AuthServiceProxy(self.__service_url, name, self.__timeout, self.__conn)

    def __call__(self, *args):
        AuthServiceProxy.__id_count += 1

        log.info("-%s-> %s %s" % (AuthServiceProxy.__id_count, self.__service_name,
                                   json.dumps(args, default=EncodeDecimal)))
        postdata = json.dumps({'version': '1.1',
                               'method': self.__service_name,
                               'params': args,
                               'id': AuthServiceProxy.__id_count}, default=EncodeDecimal)
        self.__conn.request('POST', self.__url.path, postdata,
                            {'Host': self.__url.hostname,
                             'User-Agent': USER_AGENT,
                             'Authorization': self.__auth_header,
                             'Content-type': 'application/json'})
        self.__conn.sock.settimeout(self.__timeout)

        response = self._get_response()
        if response.get('error') is not None:
            raise JSONRPCException(response['error'])
        elif 'result' not in response:
            raise JSONRPCException({
                'code': -343, 'message': 'missing JSON-RPC result'})
        self.__conn.close()
        return response['result']

    def batch_(self, rpc_calls):
        batch_data = []
        for rpc_call in rpc_calls:
            AuthServiceProxy.__id_count += 1
            m = rpc_call.pop(0)
            batch_data.append({"jsonrpc": "2.0", "method": m, "params": rpc_call, "id": AuthServiceProxy.__id_count})

        postdata = json.dumps(batch_data, default=EncodeDecimal)
        log.debug("--> " + postdata)
        self.__conn.request('POST', self.__url.path, postdata,
                            {'Host': self.__url.hostname,
                             'User-Agent': USER_AGENT,
                             'Authorization': self.__auth_header,
                             'Content-type': 'application/json'})
        results = []
        responses = self._get_response()
        for response in responses:
            if response.get('error') is not None:
                raise JSONRPCException(response['error'])
            elif 'result' not in response:
                raise JSONRPCException({
                    'code': -343, 'message': 'missing JSON-RPC result'})
            else:
                results.append(response['result'])
        return results

    def _get_response(self):
        http_response = self.__conn.getresponse()
        if http_response is None:
            raise JSONRPCException({
                'code': -342, 'message': 'missing HTTP response from server'})

        content_type = http_response.getheader('Content-Type')
        if content_type != 'application/json':
            raise JSONRPCException({
                'code': -342, 'message': 'non-JSON HTTP response with \'%i %s\' from server' % (
                http_response.status, http_response.reason)})

        responsedata = http_response.read().decode('utf8')
        response = json.loads(responsedata, parse_float=decimal.Decimal)
        if "error" in response and response["error"] is None:
            log.debug("<-%s- %s" % (response["id"], json.dumps(response["result"], default=EncodeDecimal)[:1000]))
        else:
            log.debug("<-- " + responsedata[:1000])
        return response
