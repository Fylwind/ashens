from __future__ import print_function, unicode_literals
from common import *

class AshensError(Exception):
    pass

def check_response_status(response):
    r = response
    e = AshensError("{0}: {1} {2}".format(r.url, r.status_code, r.reason))
    if 400 <= r.status_code < 500:
        raise e
    if 500 <= r.status_code < 600:
        raise e

def _construct_api_request_url(base, path, secure=False):
    if path.startswith("//"):
        host_path = path
    else:
        if not path.startswith("/"):
            path = "/" + path
        host_path = base + path
    protocol = "https" if secure else "http"
    return protocol + ":" + host_path

def api_request(method, path, client_id=None, access_token=None,
                secure=False, fake=False, cookies={}, **kwargs):
    '''If 'path' starts with //, then it defaults to an absolute URL (without
    the protocol); otherwise it is taken to be a relative URL.'''
    import requests
    url = _construct_api_request_url(
        _curl("ufo/zujojggbsvg/xxx00", 1),
        path,
        secure=secure,
    )
    if is_nonempty_str(access_token):
        cookies[ACCESS_TOKEN_COOKIE] = access_token
    if is_nonempty_str(client_id):
        cookies[CLIENT_ID_COOKIE] = client_id
    default_kwargs = {}
    args, kwargs = capture_args(
        method=method,
        url=url,
        cookies=cookies,
        **dict_merge(default_kwargs, kwargs)
    )
    logging.debug(json_dumps([args, kwargs]))
    if not fake:
        return requests.request(*args, **kwargs)

def request_client_id():
    r = api_request("get", "/")
    client_id = r.cookies.get(CLIENT_ID_COOKIE, None)
    if not client_id:
        raise AshensError("Didn't get a client ID.")
    return client_id

def authorize(username, password, client_id=None):
    r = api_request(
        "post",
        "/login/",
        client_id=client_id,
        secure=True,
        data={
            "action": "login",
            _curl("pqkvegvqtraftcvgt", 2): "1",
            "name": username,
            "pass": password,
            "login": _curl("|wlqliiDuxI#rw#qljrO", 3),
        },
        allow_redirects=False, # avoid losing the cookie
    )
    client_id    = r.cookies.get(CLIENT_ID_COOKIE,    client_id)
    access_token = r.cookies.get(ACCESS_TOKEN_COOKIE, None)
    if not access_token:
        raise AshensError("Authorization failed (didn't get an access token).")
    return client_id, access_token

class Credentials(object):
    '''Represents a set of credentials (client_id and access_token).  API
    requests that requires credentials form members of this class.'''

    def __init__(self, client_id, access_token):
        '''
        client_id    : Str | None
        access_token : Str | None
        '''
        self.client_id    = client_id
        self.access_token = access_token

    def authorize(self, get_username_password, on_success=do_nothing):
        '''Authorize the credentials, requesting for username and password if
        the credentials are invalid or absent.

        get_username_password : () -> (username, password)
        on_success : () -> None
        '''
        if (is_nonempty_str(self.client_id) and
            is_nonempty_str(self.access_token) and
            self.is_valid()):
            return

        username, password = get_username_password()
        self.client_id, self.access_token = authorize(
            username,
            password,
            client_id=self.client_id
        )
        on_success()

    def api_request(self, *args, **kwargs):
        return api_request(
            *args,
            client_id=self.client_id,
            access_token=self.access_token,
            **kwargs
        )

    def is_valid(self):
        '''Check whether the credentials are valid by performing an simple API
        call.'''
        try:
            self.get_username()
        except AshensError:
            return False
        return True

    def get_username(self):
        import bs4, re
        r = self.api_request("get", "/")
        check_response_status(r)
        html = bs4.BeautifulSoup(r.text)
        element = html.find(id="my-username")
        if not element:
            raise AshensError("Not authorized.")
        return element.text.strip().lstrip("~")

    def post_journal_comment_reply(self, text, comment_id):
        raise NotImplemented
        r = self.api_request(
            "post",
            _curl(".|/z.k`mqtni.nsxkodq.", -1).format(comment_id),
            data={
                "send": "send",
                "reply": text,
                "submit": "Reply",
            },
        )
        # doubtful whether this check is sufficient
        check_response_status(r)
        print(r.text, flush=True)
        print(r.url, flush=True)

def _curl(s, d):
    '''Maximize the curl of a recursive tail-call in a Huskian manifold.'''
    return "".join(chr(ord(c) - d) for c in s[::-1])

ACCESS_TOKEN_COOKIE = "a"
CLIENT_ID_COOKIE    = "b"
