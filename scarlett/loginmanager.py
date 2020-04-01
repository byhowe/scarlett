#!/usr/bin/env python3
from datetime import datetime

import zila
from finian import Connection, Result, current_conn as _current_conn
from passlib.hash import pbkdf2_sha512
from pymongo.database import Database

from scarlett.chatting import add_member_to_chat, accept_pending_squads, create_chat_from
from scarlett.encryption import rsa
from scarlett.logger import logger

current_conn = _current_conn.get_current_object()


# noinspection DuplicatedCode
@current_conn.protocol(80)
def register(conn: Connection, result: Result):
    logger.debug(f"Protocol:80 Register call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True,
        "message": "Successfully registered."
    }
    try:
        if "username" in conn.session:
            logger.debug(f"{conn.session['username']} tried to register.")
            raise Exception(
                "Already logged in as %s!" % conn.session["username"])
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted or not in JSON format!")
        username = result.data["username"]
        password = result.data["password"]
        confirm = result.data["confirm"]
        # pubkey = result.data["pubkey"]
        if len(
                zila.validate(username, [
                    zila.Length(min_length=4, max_length=16)]) +
                zila.validate(password, [
                    zila.Length(min_length=6, max_length=128)])) > 0 \
                or confirm != password:
            logger.debug("User inputs do not meet the requirements.")
            raise Exception("User inputs do not meet the requirements!")
        db: Database = current_conn.db
        if db.get_collection("members").find_one(
                {"username": username}) is not None:
            logger.debug(f"Username {username} was already taken.")
            raise Exception("This username has been taken!")
        password = pbkdf2_sha512.hash(password)
        post = {
            "username": username,
            "password": password,
            "timestamp": datetime.utcnow(),
            "pending_squads": [],
            "admin": False,
            "squads": [],
            "pending": True,
            # "pubkey": pubkey
        }
        _id = db.get_collection("members").insert_one(post).inserted_id
        # conn.recp_pubkey = pubkey.encode()
        conn.session["username"] = username
        conn.session["id"] = _id
        logger.info("A new user has been registered: {"
                    f"username={username}, id={str(_id)}"
                    "}")
    except Exception as e:
        response["status"] = False
        response["message"] = str(e)
    finally:
        logger.debug(str(response))
        conn.send(response, 80)


@current_conn.protocol(79)
def logout(conn: Connection, _):
    logger.debug(f"Protocol:79 Logout call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True,
        "message": "Successfully logged out."
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        # conn.recp_pubkey = None
        logger.info(f"{conn.session['username']} has been logged out.")
        conn.session.clear()
    except Exception as e:
        response["status"] = False
        response["message"] = str(e)
    finally:
        conn.send(response, 79)


# noinspection DuplicatedCode
@current_conn.protocol(78)
def login(conn: Connection, result: Result):
    logger.debug(f"Protocol:78 Login call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True,
        "message": "Successfully logged in."
    }
    try:
        if "username" in conn.session:
            logger.debug(f"{conn.session['username']} tried to login.")
            raise Exception(
                "Already logged in as %s!" % conn.session["username"])
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted or not in JSON format!")
        username = result.data["username"]
        password = result.data["password"]
        db: Database = current_conn.db
        db_response = db.get_collection("members").find_one(
            {"username": username},
            {
                "_id": True, "username": True, "password": True,
                "pending": True, "public_key": True, "admin": True
            }
        )
        if db_response is None or not pbkdf2_sha512.verify(
                password, db_response["password"]) or db_response["admin"]:
            logger.debug(f"A user failed to login as {username}.")
            raise Exception("Wrong username or password!")
        if db_response["pending"]:
            logger.debug(f"{username} is waiting for membership.")
            raise Exception(
                "Your membership hasn't been reviewed by an admin yet!")
        if "public_key" not in db_response:
            public_key, private_key = rsa.generate_key_pair()
            db.get_collection("members").update_one(
                {"_id": db_response["_id"]},
                {"$set": {
                    "public_key": rsa.serialize_public_key(public_key),
                    "private_key": rsa.serialize_private_key(private_key, password.encode())
                }}
            )
            add_member_to_chat(db, db_response["_id"], current_conn.main_squad,
                               alpha_id=current_conn.user_id, alpha_password=current_conn.args.key_pass.encode())
            contact_entry = db.get_collection("members").find(
                {"pending": False, "admin": False, "_id": {"$ne": db_response["_id"]}},
                {"_id": True}
            )
            for contact in contact_entry:
                create_chat_from(db, db_response["_id"], participant_id=contact["_id"])
        accept_pending_squads(db, db_response["_id"], password.encode())

        conn.session["squads"] = {}
        member_entry = db.get_collection("members").find_one(
            {"_id": db_response["_id"]},
            {"squads": True, "private_key": True}
        )
        private_key = rsa.load_private_key(member_entry["private_key"], password=password.encode())
        for squad in member_entry["squads"]:
            key = rsa.decrypt(private_key, squad["key"])
            conn.session["squads"][squad["id"]] = key

        response["your_id"] = str(db_response["_id"])
        response["you"] = db_response["username"]
        # conn.recp_pubkey = db_response["pubkey"]
        conn.session["username"] = username
        conn.session["id"] = db_response["_id"]
        logger.info("A new user has been logged in: {"
                    f"username={username}, id={str(db_response['_id'])}"
                    "}")
    except Exception as e:
        response["status"] = False
        response["message"] = str(e)
    finally:
        conn.send(response, 78)
