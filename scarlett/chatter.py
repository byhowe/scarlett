import base64
import os
from datetime import datetime

import rsa
import zila
from bson import ObjectId
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from finian import Connection, Result, current_conn
from passlib.hash import pbkdf2_sha512
from pymongo.database import Database

from scarlett.logger import logger


def generate_key(password: bytes, salt: bytes):
    logger.debug("Generating Fernet compatible key.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))


def encrypt(data: bytes, key: bytes):
    logger.debug("Encrypting using Fernet.")
    return Fernet(key).encrypt(data)


def decrypt(token: bytes, key: bytes):
    logger.debug("Decrypting using Fernet.")
    return Fernet(key).decrypt(token)


@current_conn.protocol(130)
def create_chat(conn: Connection, result: Result):
    logger.debug(f"Protocol:130 Create chat call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True,
        "message": "You have successfully created a chat room."
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted or not in JSON format!")
        title = result.data["title"]
        password = result.data["password"]
        if len(zila.validate(title, [zila.Length(max_length=50)])) > 0:
            logger.debug("User inputs do not meet the requirements.")
            raise Exception("Title cannot be more than 50 characters long!")
        logger.debug("Generating a new squad password.")
        squad_pass = Fernet.generate_key()
        post = {
            "title": title,
            "author": conn.session["username"],
            "timestamp": datetime.utcnow(),
            "participants": [conn.session["id"]],
            "leaders": [conn.session["id"]],
            "key": pbkdf2_sha512.hash(squad_pass)
        }
        db: Database = current_conn.db
        squad_id = db.get_collection("squads").insert_one(post).inserted_id
        salt = os.urandom(16)
        logger.debug("Encrypting the newly created squad password.")
        token = encrypt(squad_pass, generate_key(password.encode(), salt))
        db.get_collection("members").update_one(
            {"_id": conn.session["id"]},
            {"$push": {"squads": {
                "id": squad_id,
                "key": token,
                "salt": salt
            }}})
        logger.info("A new squad has been created: {"
                    f"title={title}, id={str(squad_id)}"
                    "}")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 130)


@current_conn.protocol(135)
def add_member(conn: Connection, result: Result):
    logger.debug(f"Protocol:135 Add member call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True,
        "message": "You have successfully added a member."
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted  or not in JSON format!")
        squad_id = ObjectId(result.data["squad"])
        member = result.data["member"]
        password = result.data["password"]
        db: Database = current_conn.db
        squad_entry = db.get_collection("squads").find_one(
            {"_id": squad_id},
            {"leaders": True}
        )
        if squad_entry is None:
            logger.debug("Squad does not exist: {"
                         f"id={str(squad_id)}"
                         "}")
            raise Exception("This squad does not exist!")
        if conn.session["_id"] not in squad_entry["leaders"]:
            logger.debug(f"User {conn.session['username']} tried to access"
                         " without authorization.")
            raise Exception("You are not authorized!")
        member_entry = db.get_collection("members").find_one(
            {"username": member, "pubkey": True,
             "squads": True, "pending_squads": True})
        if member_entry is None:
            logger.debug(f"Member {member} does not exist.")
            raise Exception("Member does not exist!")
        for squad in (
                member_entry["squads"] +
                member_entry["pending_squads"]
        ):
            if squad["id"] == squad_id:
                logger.debug(
                    f"Member {member} is already present in the squad")
                raise Exception(
                    "This member is already present in the squad!")
        alpha = db.get_collection("members").find_one(
            {"username": conn.session["username"]},
            {"_id": True, "squads": True})
        squad_pass_token = None
        squad_pass_salt = None
        for squad in alpha["squads"]:
            if squad["id"] == squad_id:
                squad_pass_token = squad["key"]
                squad_pass_salt = squad["salt"]
                break
        logger.debug("Squad password is being decrypted.")
        squad_pass = decrypt(squad_pass_token, generate_key(password,
                                                            squad_pass_salt))
        logger.debug("Squad password is being encrypted using member"
                     " candidate's RSA public key.")
        token = rsa.encrypt(
            squad_pass,
            rsa.key.PublicKey.load_pkcs1(member_entry["pubkey"])
        )
        db.get_collection("members").update_one(
            {"username": member},
            {"$push": {"pending_squads": {
                "id": squad_id,
                "key": token
            }}})
        mem_conn = current_conn.find_member(username=member)
        if mem_conn is not None:
            logger.info("Sending notification to the member candidate.")
            mem_conn.send(None, 140)
        logger.info(f"Member {member} has been invited to the squad.")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 135)


@current_conn.protocol(132)
def get_invitations(conn: Connection, result: Result):
    logger.debug(f"Protocol:132 Get invitations call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted  or not in JSON format!")
        db: Database = current_conn.db
        member = db.get_collection("members").find_one(
            {"username": conn.session["username"]},
            {"pending_squads"}
        )
        squads = member["pending_squads"].copy()
        for squad in squads:
            squad["id"] = str(squad["id"])
        response["squads"] = squads
        logger.info(f"Sending {str(len(squads))} invitation(s) back.")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 132)


@current_conn.protocol(131)
def accept_invitations(conn: Connection, result: Result):
    logger.debug(f"Protocol:131 Accept invitations call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True,
        "message": "You have successfully accepted all invitations."
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted or not in JSON format!")
        password = result.data["password"]
        squads = result.data["squads"]
        posts = []
        squad_ids = []
        logger.debug(f"Accepting {str(len(squads))} invitations"
                     f" for {conn.session['username']}")
        for squad in squads:
            key = squad["key"]
            squad_id = ObjectId(squad["id"])
            squad_ids.append(squad_id)
            salt = os.urandom(16)
            logger.debug("Encrypting the password: {"
                         f"id={squad['id']}"
                         "}")
            token = encrypt(key, generate_key(password.encode(), salt))
            posts.append({
                "id": squad_id,
                "key": token,
                "salt": salt
            })
        db: Database = current_conn.db
        db.get_collection("members").update_one(
            {"username": conn.session["username"]},
            {
                "$push": {"squads": {"$each": posts}},
                "$pullAll": {"pending_squads.id": squad_ids}
            }
        )
        db.get_collection("squads").update_many(
            {"_id": {"$in": squad_ids}},
            {"$push": {"participants": conn.session["id"]}}
        )
        logger.info("Accepted all invitations.")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 131)


@current_conn.protocol(136)
def get_squads(conn: Connection, _):
    logger.debug(f"Protocol:136 Get squads call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("Your are not logged in!")
        db: Database = current_conn.db
        post = []
        for squad in db.get_collection("squads").find(
                {"participants": conn.session["id"]},
                {"title": True, "participants": True, "_id": True}
        ):
            post_ = []
            participants = db.get_collection("members").find(
                {"_id": {"$in": squad["participants"]}},
                {"username": True, "_id": True}
            )
            for participant in participants:
                post_.append({
                    "username": participant["username"],
                    "id": participant["_id"]
                })
            post.append({
                "title": squad["title"],
                "id": str(squad["_id"]),
                "participants": post_
            })
        response["squads"] = post
        logger.info(f"Sending a list of {str(len(post))} squads(s) back.")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 136)


# noinspection DuplicatedCode
@current_conn.protocol(150)
def broadcast_message(conn: Connection, result: Result):
    logger.debug(f"Protocol:150 Broadcast message call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted or not in JSON format!")
        squad_id = ObjectId(result.data["squad"])
        message = result.data["message"]
        db: Database = current_conn.db
        squad_entry = db.get_collection("squads").find_one(
            {"_id": squad_id},
            {"participants": True}
        )
        if squad_entry is None:
            logger.debug("Squad does not exist.")
            raise Exception("This squad does not exist!")
        members = squad_entry["participants"]
        logger.debug(f"Sending message to {str(len(members))} members.")
        for member in members:
            mem_conn: Connection = current_conn.find_member(
                member_id=member)
            mem_conn.send({
                "message": message,
                "from": conn.session["username"],
                "squad": str(squad_id)
            }, 151)
        db.get_collection("messages").insert_one({
            "from": conn.session["username"],
            "timestamp": datetime.utcnow(),
            "message": message,
            "squad": squad_id
        })
        logger.info("Broadcast message to squad members.")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 150)


# noinspection DuplicatedCode
@current_conn.protocol(153)
def get_messages(conn: Connection, result: Result):
    logger.debug(f"Protocol:153 Broadcast message call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        if "username" not in conn.session:
            logger.debug("User was not logged in.")
            raise Exception("You are not logged in!")
        if not result.json or result.encrypted:
            logger.warning("Result is encrypted or not in JSON format!")
            raise Exception("Result is encrypted or not in JSON format!")
        squad_id = ObjectId(result.data["squad"])
        posts = []
        db: Database = current_conn.db
        for message in db.get_collection("messages").find({
            "squad": squad_id
        }).limit(50).sort("timestamp"):
            posts.append({
                "from": message["from"],
                "timestamp": str(message["timestamp"]),
                "message": message["message"],
                "id": str(message["_id"])
            })
        response["squad"] = str(squad_id)
        response["messages"] = posts
        logger.info(f"Returning a list of {str(len(posts))} messages.")
    except Exception as e:
        response["status"] = False
        response["message"] = e
    finally:
        conn.send(response, 153)
