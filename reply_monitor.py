#!/usr/bin/env python
from __future__ import print_function, unicode_literals
from common import *
import ashens

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
    credentials  = ashens.Credentials(**restore_credentials())
    credentials.authorize(prompt_login_info, on_success=print_login_success)
    save_credentials(credentials.__dict__)
    return credentials

def find_next_comments(credentials, comment_id):
    journal_id = ashens.journal_id_from_comment_id(comment_id)
    comments = credentials.get_journal_comments(journal_id)["comments"]
    comment = comments[comment_id]
    replies = comment["replies"]
    # if at nesting limit, search siblings; otherwise search children
    if replies is None:
        parent_comment = comments[comment["in_reply_to"]]
        parent_replies = parent_comment["replies"]
        index = parent_replies.index(comment_id)
        if index + 1 < len(parent_replies):
            return [comments[c] for c in parent_replies[index + 1:]]
    elif replies:
        return [comments[c] for c in replies]
    return []

def check_for_replies(credentials, db):
    comment_id = db["last_comment_id"]
    replies = [c for c in find_next_comments(credentials, comment_id)
               if "content" in c
               and c["content"] == db["content"]
               and c["username"].lower() == db["username"].lower()]
    if not replies:
        print("No reply yet", flush=True)
        return
    comment_id = replies[0]["id"]
    comment_id = credentials.reply_journal_comment(db["content"], comment_id)
#    comment_id = find_next_comment(credentials, comment_id)
    db["last_comment_id"] = comment_id

def random_sleep(mean):
    import random, time
    interval = random.expovariate(1. / mean)
    logging.info("sleeping for {0:.1f} s.".format(interval))
    time.sleep(interval)

def main():
    import random
    random.seed()
    credentials = obtain_credentials()
    interval = 300.
    while True:
        reply_monitor_db = json_load_file(REPLY_MONITOR_DB_FILENAME)
        check_for_replies(credentials, reply_monitor_db)
        json_dump_file(REPLY_MONITOR_DB_FILENAME, reply_monitor_db)
        random_sleep(interval)

CREDENTIALS_FILENAME = "ashens_credentials.json"
CREDENTIALS_FIELDS = ["access_token", "client_id"]

REPLY_MONITOR_DB_FILENAME = "reply_monitor.json"

if __name__ == "__main__":
    init_logging("INFO")
    try:
        main()
    except UserError as e:
        logging.error(e)
        exit(1)
    except ashens.AshensError as e:
        logging.error(e)
        exit(1)
    except KeyboardInterrupt:
        exit(2)
