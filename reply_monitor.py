#!/usr/bin/env python
from __future__ import print_function, unicode_literals
from common import *
import ashens
import requests

class UserError(Exception):
    pass

def random_discrete_distribution(distribution):
    import random
    distribution = tuple(distribution)  # prevent it from being changed
    r = random.random() * sum(p for _, p in distribution)
    cumulative = 0.
    for reply, probability in distribution:
        cumulative += probability
        if r < cumulative:
            return reply
    if distribution:
        return distribution[-1][0]

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

def generate_reply(reply_matrix, content):
    candidates = reply_matrix.get(content, None)
    if candidates is None:
        return
    return random_discrete_distribution(candidates.items())

def comment_predicate(reply_matrix, usernames):
    usernames = set(x.lower() for x in usernames)
    return lambda c: ("content" in c and
                      generate_reply(reply_matrix, c["content"]) and
                      c["username"].lower() in usernames)

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
    username = credentials.get_username().lower()
    last_id = db["last_comment_id"]
    journal_id = ashens.journal_id_from_comment_id(last_id)
    comments = credentials.get_journal_comments(journal_id)["comments"]
    last = comments[last_id]

    # for filtering tweets
    predicate = comment_predicate(db["reply_matrix"],
                                  tuple(db["participants"]) + (username,))

    # make sure we are looking at the right tweet
    assert predicate(last)

    # skip to the latest
    latest = find_latest(comments, last, [predicate])
    if not latest or latest["username"].lower() == username:
        print("No reply yet", flush=True)
        return

    reply = generate_reply(db["reply_matrix"], latest["content"])
    new_id = credentials.reply_journal_comment(reply, latest["id"])
    print("Replied: " + reply, flush=True)
    db["last_comment_id"] = new_id

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
        try:
            check_for_replies(credentials, reply_monitor_db)
        except requests.exceptions.ConnectionError as e:
            logging.error(str(e))
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
