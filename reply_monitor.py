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

def find_replies(comments, comment_id):
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

def find_reply_where(comments, comment_id, pred):
    replies = tuple(filter(pred, find_replies(comments, comment_id)))
    if not replies:
        return
    return replies[0]

def comment_predicate(content, username):
    return lambda c: ("content" in c and
                      c["content"] == content and
                      c["username"].lower() == username.lower())

def find_latest(comments, comment, preds):
    '''Continue down the chain of replies, verifying with the cyclic sequence
    of preds.'''
    latest_comment = comment
    while True:
        for pred in preds:
            comment = find_reply_where(comments, comment["id"], pred)
            if not comment:
                return latest_comment
        latest_comment = comment
    return latest_comment

def check_for_replies(credentials, db):
    username = credentials.get_username()
    last_id = db["last_comment_id"]
    journal_id = ashens.journal_id_from_comment_id(last_id)
    comments = credentials.get_journal_comments(journal_id)["comments"]
    last = comments[last_id]

    # make sure we are looking at the right tweet
    assert ("content" in last and
            last["content"] == db["content"] and
            last["username"].lower() == username.lower())

    # skip to the latest if we missed any
    theirs_predicate = comment_predicate(db["content"], db["username"])
    mine_predicate   = comment_predicate(db["content"], username)
    last = find_latest(comments, last, [theirs_predicate, mine_predicate])

    reply = find_reply_where(comments, last["id"], theirs_predicate)
    if not reply:
        print("No reply yet", flush=True)
        db["last_comment_id"] = last["id"]
        return

    new = credentials.reply_journal_comment(db["content"], reply["id"])
    db["last_comment_id"] = new["id"]

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
