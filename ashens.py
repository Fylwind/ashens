from __future__ import print_function, unicode_literals
from common import *

class AshensError(Exception):
    pass

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
        r = self.api_request("get", "/")
        check_response_status(r)
        username = _check_login(r.text)
        return username

    def get_timezone(self):
        '''Obtain the timezone offset as a 'datetime.timedelta'.'''
        import datetime
        r = self.api_request("get", "/controls/settings/")
        check_response_status(r)
        html = _soup(r.text)
        timezone_option = html.find(attrs={"name": "timezone"}).find(selected="selected")
        if not timezone_option:
            raise AshensError("Failed to obtain valid timezone.")
        timezone_str = timezone_option["value"]
        hours   = int(timezone_str[:-2])
        minutes = int(timezone_str[-2:])
        timezone = datetime.timedelta(hours=abs(hours), minutes=minutes)
        if hours < 0:
            timezone *= -1
        if html.find(attrs={"name": "timezone_dst"}).get("checked", None):
            timezone += datetime.timedelta(hours=1)
        return timezone

    def get_journal(self, journal_id, timezone=True):
        '''
        timezone: Whether the journal timestamp uses UTC or local time.
        It can be one of the following:
          - True: request the timezone offset and convert to UTC
          - False | None: return the local time
          - datetime.timedelta(...): use the given timezone offset
        This does not affect the timestamps of comments.  Note that this can
        introduce a race condition if the timezone is modified elsewhere
        in the meantime.
        '''
        journal_id = str(journal_id)
        r = self.api_request("get", "/journal/{0}/".format(journal_id))
        check_response_status(r)
        if timezone is True:
            timezone = self.get_timezone()
        elif timezone is False or timezone is None:
            timezone = None
        return _parse_journal(journal_id, r.text, timezone=timezone)

    def get_journal_comments(self, journal_id):
        '''Similar to 'get_journal' but strips info not related to comments.'''
        j = self.get_journal(journal_id, timezone=None)
        return dict((k, v) for k, v in j.items()
                    if k in ("top_level_comments", "comments"))

    def reply_journal_comment(self, text, comment_id):
        journal_id, comment_subid = _split_journal_comment_id(comment_id)
        if comment_subid.startswith("unknown"):
            raise AshensError("Cannot reply to an unknown comment.")

#        raise NotImplementedError()
        global r

        r = self.api_request(
            "post",
            _curl(".|/z.k`mqtni.nsxkodq.", -1).format(comment_subid),
            data={
                "send": "send",
                "reply": text,
                "submit": "Reply",
            },
            allow_redirects=False,
        )
        check_response_status(r)
        decorated_subid = r.headers["Location"].split("#")[1]
        new_subid = strip_prefix(_JC_ID_PREFIX, decorated_subid)
        return journal_id + _JC_ID_SEP + new_subid

def _curl(s, d):
    '''Maximize the curl of a recursive tail-call in a Huskian manifold.'''
    return "".join(chr(ord(c) - d) for c in s[::-1])

def _soup(code):
    import bs4
    return bs4.BeautifulSoup(code, "html")

def _parse_username(text):
    html = _soup(text)
    element = html.find(id="my-username")
    if not element:
        return None
    return element.text.strip().lstrip("~")

def _check_login(text):
    '''Return the username if the user is logged in, otherwise abort.'''
    username = _parse_username(text)
    if not username:
        raise AshensError("Not authorized.")
    return username

def _dump_visible(text):
    import bs4, re
    invisible_elements = ("[document]", "head", "script", "style", "title")
    return "".join(
        e for e in _soup(text).findAll(text=True)
        if not (e.parent.name in invisible_elements or
                isinstance(e, bs4.Comment))
    )

def _parse_timestamp(time):
    import datetime
    return datetime.datetime.utcfromtimestamp(float(time))

def _parse_time(time):
    import dateutil.parser
    return dateutil.parser.parse(time)

def _format_time(time, utc=True):
    return time.isoformat() + ("Z" if utc else "")

def _reformat_time(time, timezone=None):
    t = _parse_time(time)
    if timezone is None:
        t = _format_time(t, utc=False)
    else:
        t = _format_time(t - timezone)
    return t

def _parse_journal_comments(journal_id, html):
    import re
    comments_td = html.find(id="page-comments")
    comment_tables = [c for c in comments_td.children
                      if c.name == "table"
                      and "container-comment" in c["class"]]

    comments = [dict_merge(
        {"width": parse_percentage(c["width"])},
        {} if not c.has_attr("id") else {
            "id": (journal_id + _JC_ID_SEP +
                   strip_prefix(_JC_ID_PREFIX, c["id"])),
            "username": c.find(attrs={"class": "replyto-name"}).text,
            "time": _format_time(_parse_timestamp(c["data-timestamp"])),
            "edited": bool(c.find(attrs={"class": "lead"})
                           .find(src="/themes/classic/img/edited.png")),
            "content": re.match(
                "\s*(.*?)\s*(<br/>)*\s*$",
                c.find(attrs={"class": "replyto-message"}).decode_contents()
            ).group(1),
        },
    ) for c in comment_tables]

    # reconstruct the hierarchy of the comments based on the width,
    # which may be inaccurate due to the _JC_MIN_WIDTH restriction;
    # when the width is at a minimum we assume they are independent replies
    # but this is only a guess; for the comments at _JC_MIN_WIDTH, the
    # "replies" attribute is set to None as a reminder
    stack = [{"id": None, "replies": [], "width": float("inf")}]
    path = ["unknown"]
    for comment in comments:
        width = comment["width"]
        while width - stack[-1]["width"] >= 0:
            stack.pop()
            path.pop()
        path.append(str(len(stack[-1]["replies"])))
        if "id" not in comment:
            comment["id"] = journal_id + _JC_ID_SEP + "_".join(path)
        comment["replies"] = [] if width > _JC_MIN_WIDTH else None
        comment["in_reply_to"] = stack[-1]["id"]
        stack[-1]["replies"].append(comment["id"])
        stack.append(comment)

    for comment in comments:
        del comment["width"]

    comments_dict = dict((c["id"], c) for c in comments)
    top_level_comments = stack[0]["replies"]
    return comments_dict, top_level_comments

def _parse_journal(journal_id, code, timezone=None):
    html = _soup(code)
    journal_table = html.find(attrs={"class": "maintable"})
    [title_div, content_div] = journal_table.find_all(
        attrs={"class": "no_overflow"})
    time_span = journal_table.find(attrs={"class": "popup_date"})
    comments, top_level_comments = _parse_journal_comments(journal_id, html)
    journal = {
        "id": journal_id,
        "username": time_span.parent.a.text,
        "time": _reformat_time(time_span.text, timezone=timezone),
        "title": title_div.text.strip(),
        "content": content_div.decode_contents().strip(),
        "comments": comments,
        "top_level_comments": top_level_comments,
    }
    return journal

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
        cookies[_ACCESS_TOKEN_COOKIE] = access_token
    if is_nonempty_str(client_id):
        cookies[_CLIENT_ID_COOKIE] = client_id
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
    client_id = r.cookies.get(_CLIENT_ID_COOKIE, None)
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
    client_id    = r.cookies.get(_CLIENT_ID_COOKIE,    client_id)
    access_token = r.cookies.get(_ACCESS_TOKEN_COOKIE, None)
    if not access_token:
        raise AshensError("Authorization failed (didn't get an access token).")
    return client_id, access_token

def _split_journal_comment_id(comment_id):
    return comment_id.split(_JC_ID_SEP)

def journal_id_from_comment_id(comment_id):
    return _split_journal_comment_id(comment_id)[0]

# credentials
_ACCESS_TOKEN_COOKIE = "a"
_CLIENT_ID_COOKIE    = "b"

# journal comments
_JC_MIN_WIDTH = .4
_JC_ID_PREFIX = "cid:"
_JC_ID_SEP = "."
