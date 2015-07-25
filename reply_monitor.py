#!/usr/bin/env python
from __future__ import print_function, unicode_literals
from common import *
from ashens import *

class UserError(Exception):
    pass

def prompt_login_info():
    import getpass, sys
    print("Authorization required.")
    username = input("  Username: ")
    password = getpass.getpass("  Password: ")
    if not username:
        raise UserError("Invalid username.")
    return username, password

def print_login_success():
    print("Authorized.", flush=True)

def restore_credentials():
    credentials = json_load_file(CREDENTIALS_FILENAME, fallback={})
    for k, v in credentials.items():
        if k not in CREDENTIALS_FIELDS:
            logging.warning("Removing unknown item in credentials ({0}: {1})"
                            .format(repr(k), repr(v)))
            del credentials[k]
    for k in CREDENTIALS_FIELDS:
        if k not in credentials:
            credentials[k] = None
    return credentials

def save_credentials(credentials):
    json_dump_file(CREDENTIALS_FILENAME, credentials)

def obtain_credentials():
    credentials  = Credentials(**restore_credentials())
    credentials.authorize(prompt_login_info, on_success=print_login_success)
    save_credentials(credentials.__dict__)
    return credentials

def find_next_comment(credentials, journal_id, last_reply_id):
    import bs4, re

    r = credentials.api_request("get", "/journal/{0}/".format(journal_id))
    assert r.status_code == 200

    html = bs4.BeautifulSoup(r.text)
    last_reply_table = html.find(id="cid:" + last_reply_id)
    last_reply_table_width = parse_percentage(last_reply_table["width"])
    next_reply_table = last_reply_table
    while True:
        next_reply_table = next_reply_table.next_sibling
        if next_reply_table.name is not None:
            break
    if next_reply_table.name != "table":
        raise Exception("I expected a <table>!")
    next_reply_table_width = parse_percentage(next_reply_table["width"])
    if not (next_reply_table_width == .4 or
            next_reply_table_width < last_reply_table_width):
        return
    new_reply_id = re.match("cid:([0-9]+)$", next_reply_table["id"]).group(1)
    return new_reply_id

def process_last_reply(credentials, last_reply_info):
    journal_id    = last_reply_info["journal_id"]
    last_reply_id = last_reply_info["last_reply_id"]
    current_reply_id = find_next_comment(credentials, journal_id, last_reply_id)
    if not current_reply_id:
        print("No reply yet", flush=True)
        return
    credentials.post_journal_comment_reply(":3", current_reply_id)
    new_reply_id = find_next_comment(credentials, journal_id, current_reply_id)
    last_reply_info["last_reply_id"] = new_reply_id

def handle_last_reply(credentials):
    last_reply_filename = "last_reply.json"
    last_reply_info = json_load_file(last_reply_filename)
    process_last_reply(credentials, last_reply_info)
    json_dump_file(last_reply_filename, last_reply_info)

def random_sleep(mean):
    import random, time
    interval = random.expovariate(1. / mean)
    logging.info("sleeping for {0:.1f} s.".format(interval))
    time.sleep(interval)

def main():
    import random
    random.seed()

    credentials = obtain_credentials()

    interval = 60.
    while True:
        handle_last_reply(credentials)
        random_sleep(interval)

CREDENTIALS_FILENAME = "ashens_credentials.json"
CREDENTIALS_FIELDS = ["access_token", "client_id"]

if __name__ == "__main__":
    init_logging("INFO")
    try:
        main()
    except UserError as e:
        logging.error(e)
        exit(1)
    except AshensError as e:
        logging.error(e)
        exit(1)
