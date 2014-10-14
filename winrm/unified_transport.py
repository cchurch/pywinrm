import sys
import functools

from winrm.exceptions import WinRMTransportError, UnauthorizedError

HAVE_KERBEROS=False
try:
    import kerberos
    HAVE_KERBEROS=True
except ImportError:
    pass

is_py2 = sys.version[0] == '2'
if is_py2:
    from urllib2 import Request, URLError, HTTPError, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm
    from urllib2 import OpenerDirector, BaseHandler, AbstractHTTPHandler
    from urllib2 import UnknownHandler, HTTPDefaultErrorHandler, HTTPRedirectHandler, HTTPErrorProcessor
    from urlparse import urlparse
    from httplib import HTTPConnection, HTTPSConnection
else:
    from urllib.request import Request, URLError, HTTPError, HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm
    from urllib.request import OpenerDirector, BaseHandler, AbstractHTTPHandler
    from urllib.request import UnknownHandler, HTTPDefaultErrorHandler, HTTPRedirectHandler, HTTPErrorProcessor
    from urllib.parse import urlparse
    from http.client import HTTPConnection, HTTPSConnection


class WinRMHTTPHandler(AbstractHTTPHandler):
    '''
    HTTP(S) connection handler for WinRM; to support keep-alive connections
    between requests.
    '''

    def do_open(self, http_class, req):
        # FIXME: Support keep-alive connections!
        return AbstractHTTPHandler.do_open(self, http_class, req)

    def http_open(self, req):
        return self.do_open(HTTPConnection, req)

    def http_request(self, req):
        return self.do_request_(req)

    def https_open(self, req):
        return self.do_open(HTTPSConnection, req)

    def https_request(self, req):
        return self.do_request_(req)


class TimeoutErrorHandler(BaseHandler):
    '''
    '''

    def http_error_500(self, req, fp, code, msg, hdrs):
        print req, fp, code, msg, hdrs # FIXME


class BasicAuthHandler(HTTPBasicAuthHandler):
    '''
    Basic auth handler for WinRM; only retry once to minimize chances of
    triggering account lockout.
    '''

    def reset_retry_count(self):
        self.retried = 5


class KerberosAuthHandler(BaseHandler):
    '''
    Implementation based on http://ncoghlan_devs-python-notes.readthedocs.org/en/latest/python_kerberos.html
    '''

    handler_order = 450 # Before basic auth handler.

    def __init__(self, realm=None, service=None, keytab=None):
        """
        Uses Kerberos/GSS-API to authenticate (and eventually encrypt) messages.

        @param string realm: the Kerberos realm we are authenticating to
        @param string service: the service name, default is HTTP
        @param string keytab: the path to a keytab file if you are using one
        """
        self.realm = realm
        self.service = service
        self.keytab = keytab
        self.retried = 0

    def reset_retry_count(self):
        self.retried = 0

    def http_error_401(self, req, fp, code, msg, headers):
        authreq = headers.get('www-authenticate', None)
        if self.retried > 5:
            # Don't fail endlessly - if we failed once, we'll probably
            # fail a second time. Hm. Unless the Password Manager is
            # prompting for the information. Crap. This isn't great
            # but it's better than the current 'repeat until recursion
            # depth exceeded' approach <wink>
            raise HTTPError(req.get_full_url(), 401, "kerb auth failed",
                            headers, None)
        else:
            self.retried += 1
        response = None
        if authreq:
            print authreq
            negotiate = False
            for field in authreq.split(','):
                scheme, _, details = field.strip().partition(' ')
                if scheme.lower() == 'negotiate':
                    negotiate = True
                    break
            if negotiate:
                response = self.retry_http_negotiate_auth(req)
                if response and response.code != 401:
                    self.retried = 0
        self.reset_retry_count()
        return response

    def retry_http_negotiate_auth(self, req):
        service = self.service or 'HTTP'
        realm = self.realm or urlparse(req.get_full_url()).hostname
        krb_service = '{0}@{1}'.format(service, realm)
        krb_context = kerberos.authGSSClientInit(krb_service)[1]
        print krb_service, krb_context
        kerberos.authGSSClientStep(krb_context, '')
        # TODO authGSSClientStep may raise following error:
        #GSSError: (('Unspecified GSS failure.  Minor code may provide more information', 851968), ("Credentials cache file '/tmp/krb5cc_1000' not found", -1765328189))
        gss_response = kerberos.authGSSClientResponse(krb_context)
        auth = 'Negotiate {0}'.format(gss_response)
        if req.headers.get('Authorization', None) == auth:
            return None
        req._krb_context = krb_context
        req.add_unredirected_header('Authorization', auth)
        return self.parent.open(req, timeout=req.timeout)

    def http_response(self, req, resp):
        authreq = resp.headers.get('www-authenticate', None)
        krb_context = getattr(req, '_krb_context', None)
        print authreq, krb_context
        if krb_context and authreq:
            auth_details = ''
            for field in authreq.split(','):
                scheme, _, details = field.strip().partition(' ')
                if scheme.lower() == 'negotiate':
                    auth_details = details.strip()
                    break
            kerberos.authGSSClientStep(krb_context, auth_details)
            #print('User {0} authenticated successfully using Kerberos authentication'.format(kerberos.authGSSClientUserName(krb_context)))
            kerberos.authGSSClientClean(krb_context)
            setattr(req, '_krb_context', None)
        return resp

    def https_response(self, req, resp):
        return self.http_response(req, resp)


class CertAuthHandler(BaseHandler):
    '''
    '''

    handler_order = 400 # Before default HTTPS handler and other auth.

    def __init__(self, cert_pem, cert_key_pem):
        self.cert_pem = cert_pem
        self.cert_key_pem = cert_key_pem
        # FIXME
        #self._headers['Authorization'] = "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual"

    def https_open(self, req):
        http_class = functools.partial(HTTPSConnection, key_file=self.cert_key_pem, cert_file=self.cert_pem)
        return self.do_open(http_class, req)


class Transport(object):
    
    def __init__(self, endpoint, username=None, password=None, realm=None, service=None, keytab=None, ca_trust_path=None, cert_pem=None, cert_key_pem=None, timeout=None):
        self.endpoint = endpoint
        self.username = username
        self.password = password
        self.realm = realm
        self.service = service
        self.keytab = keytab
        self.ca_trust_path = ca_trust_path
        self.cert_pem = cert_pem
        self.cert_key_pem = cert_key_pem
        self.timeout = timeout
        self.default_headers = {
            'Content-Type': 'application/soap+xml;charset=UTF-8',
            'User-Agent': 'Python WinRM client',
        }
        self.opener = None

    def build_opener(self):
        opener = OpenerDirector()
        opener.add_handler(UnknownHandler())
        opener.add_handler(HTTPDefaultErrorHandler())
        opener.add_handler(HTTPRedirectHandler())
        opener.add_handler(HTTPErrorProcessor())

        opener.add_handler(WinRMHTTPHandler())
        opener.add_handler(TimeoutErrorHandler())

        if self.username and self.password:
            password_manager = HTTPPasswordMgrWithDefaultRealm()
            basic_auth_handler = BasicAuthHandler(password_manager)
            basic_auth_handler.add_password(None, self.endpoint, self.username, self.password)
            opener.add_handler(basic_auth_handler)

        if HAVE_KERBEROS:
            kerberos_auth_handler = KerberosAuthHandler(self.realm, self.service, self.keytab)
            opener.add_handler(kerberos_auth_handler)

        if self.cert_pem and self.cert_key_pem:
            cert_auth_handler = CertAuthHandler(self.cert_pem, self.cert_key_pem)
            opener.add_handler(cert_auth_handler)

        return opener

    def send_message(self, message):
        # TODO current implementation does negotiation on each HTTP request which is not efficient
        # TODO support kerberos session with message encryption
        headers = self.default_headers.copy()
        headers['Content-Length'] = len(message)

        if not self.opener:
            self.opener = self.build_opener()
        request = Request(self.endpoint, data=message, headers=headers)
        try:
            response = self.opener.open(request, timeout=self.timeout)
            # Version 1.1 of WinRM adds the namespaces in the document instead of the envelope so we have to
            # add them ourselves here. This should have no affect version 2.
            response_text = response.read()
            return response_text
            #doc = ElementTree.fromstring(response.read())
            #Ruby
            #doc = Nokogiri::XML(resp.http_body.content)
            #doc.collect_namespaces.each_pair do |k,v|
            #    doc.root.add_namespace((k.split(/:/).last),v) unless doc.namespaces.has_key?(k)
            #end
            #return doc
            #return doc
        except HTTPError as ex:
            if ex.code == 401:
                raise UnauthorizedError(transport='plaintext', message=ex.msg)
            response_text = ex.read()
            # Per http://msdn.microsoft.com/en-us/library/cc251676.aspx rule 3,
            # should handle this 500 error and retry receiving command output.
            if 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive' in message and 'Code="2150858793"' in response_text:
                # TODO raise TimeoutError here instead of just return text
                return response_text
            error_message = 'Bad HTTP response returned from server. Code {0}'.format(ex.code)
            if ex.msg:
                error_message += ', {0}'.format(ex.msg)
            raise WinRMTransportError('http', error_message)
        except URLError as ex:
            raise WinRMTransportError('http', ex.reason)
