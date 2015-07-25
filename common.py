from __future__ import print_function, unicode_literals

import sys
if sys.version_info < (3, 0):

    def input(prompt=""):
        # workaround: Python 2 doesn't flush
        print(prompt, end="", flush=True)
        return raw_input()

    _print = print
    def print(*args, **kwargs):
        flush = False
        if "flush" in kwargs:
            flush = kwargs["flush"]
            del kwargs["flush"]
        _print(*args, **kwargs)
        if flush:
            import sys
            sys.stdout.flush()

    str = unicode

# ----------------------------------------------------------------------------

import logging

class ColoredFormatter(logging.Formatter):
    colors = {
        "DEBUG": "\033[1m",
        "INFO": "\033[1;32m",
        "WARNING": "\033[1;35m",
        "ERROR": "\033[1;31m",
        "CRITICAL": "\033[1;41m",
    }
    def format(self, record, *args, **kwargs):
        levelname = record.levelname
        if levelname in self.colors:
            record.levelname = self.colors[levelname] + "::\033[0m"
        return super(ColoredFormatter, self).format(record, *args, **kwargs)

def init_logging(level="WARNING"):
    import logging
    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter("%(levelname)s %(message)s"))
    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, level))

# ----------------------------------------------------------------------------

def do_nothing(*args, **kwargs):
    pass

def capture_args(*args, **kwargs):
    return args, kwargs

def is_nonempty_str(s):
    return isinstance(s, str) and s

def dict_merge(d1, d2):
    '''Merge two dicts and returns the result.  The original dicts are
    unchanged.  Note that this operation is biased: if a key exists in both
    dicts, the one in the right dict is chosen.'''
    d = dict(d1)
    d.update(d2)
    return d

def dict_get_or_acquire(dict, name, acquire_func, validate_func=lambda _: True):
    '''Obtain the value with a given key from the dict if it exists,
    or acquire a new one and store it in the dict.'''
    try:
        x = dict[name]
    except KeyError:
        valid = False
    else:
        valid = validate_func(x)
    if not valid:
        x = acquire_func()
        dict[name] = x
    return x

def parse_percentage(s):
    s = s.strip()
    if not s.endswith("%"):
        return float(s)
    s = s[:-1]
    return float(s) / 100.

def json_load_file(filename, fallback=None, json_args={}, **open_args):
    import json
    try:
        with open(filename, **open_args) as f:
            return json.load(f, **json_args)
    except Exception:
        if fallback is not None:
            return fallback
        raise

def json_dump_file(filename, data, json_args={}, **open_args):
    import json
    with open(filename, "w", **open_args) as f:
        json.dump(data, f, **dict_merge(JSON_FORMAT, json_args))
        f.write("\n")

def json_dumps(data, **kwargs):
    import json
    return json.dumps(data, **dict_merge(JSON_FORMAT, kwargs))

JSON_FORMAT = {"sort_keys": True, "indent": 4, "separators": (',', ': ')}
