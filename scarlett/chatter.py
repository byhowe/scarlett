import os
from datetime import datetime

from bson import ObjectId
from finian import Connection, Result, current_conn as _current_conn
from pymongo.database import Database

from scarlett.logger import logger
from scarlett.encryption import fernet
from scarlett.validators import is_logged_in, is_result_valid

current_conn = _current_conn.get_current_object()


# @current_conn.protocol(130)
# def create_chat(conn: Connection, result: Result):
#     logger.debug(f"Protocol:130 Create chat call from"
#                  f" {conn.socket.socket.getpeername()}")
#     response = {
#         "status": True,
#         "message": "You have successfully created a chat room."
#     }
#     try:
#         is_logged_in(conn)
#         is_result_valid(result)
#         title = result.data["title"]
#         create_chat_from(conn.session["id"], title=title)
#     except Exception as e:
#         response["status"] = False
#         response["message"] = str(e)
#     finally:
#         conn.send(response, 130)


# @current_conn.protocol(135)
# def add_member(conn: Connection, result: Result):
#     logger.debug(f"Protocol:135 Add member call from"
#                  f" {conn.socket.socket.getpeername()}")
#     response = {
#         "status": True,
#         "message": "You have successfully added a member."
#     }
#     try:
#         is_logged_in(conn)
#         is_result_valid(result)
#         squad_id = ObjectId(result.data["squad_id"])
#         member_id = ObjectId(result.data["member_id"])
#         add_member_to_chat(member_id, squad_id)
#     except Exception as e:
#         response["status"] = False
#         response["message"] = str(e)
#     finally:
#         conn.send(response, 135)


@current_conn.protocol(132)
def get_invitations(conn: Connection, result: Result):
    logger.debug(f"Protocol:132 Get invitations call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        is_logged_in(conn)
        is_result_valid(result)
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
        response["message"] = str(e)
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
        is_logged_in(conn)
        is_result_valid(result)
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
            token = fernet.encrypt(key, fernet.generate_key_from_password(password.encode(), salt))
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
        response["message"] = str(e)
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
        is_logged_in(conn)
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
        response["message"] = str(e)
    finally:
        conn.send(response, 136)


@current_conn.protocol(180)
def get_contacts(conn: Connection, _):
    logger.debug(f"Protocol:180 Get contacts call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        is_logged_in(conn)
        db: Database = current_conn.db
        contacts = db.get_collection('members').find(
            {"username": {"$ne": conn.session['username']}, "pending": False},
            {"username": True, "_id": True}
        )
        post = []
        for contact in contacts:
            post.append({"username": contact['username'], "id": str(contact['_id'])})
        response["contacts"] = post
    except Exception as e:
        response['status'] = False
        response['message'] = str(e)
    finally:
        conn.send(response, 180)


# noinspection DuplicatedCode
@current_conn.protocol(150)
def broadcast_message(conn: Connection, result: Result):
    logger.debug(f"Protocol:150 Broadcast message call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        is_logged_in(conn)
        is_result_valid(result)
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
        response["message"] = str(e)
    finally:
        conn.send(response, 150)


# noinspection DuplicatedCode
@current_conn.protocol(153)
def get_messages(conn: Connection, result: Result):
    logger.debug(f"Protocol:153 Get messages call from"
                 f" {conn.socket.socket.getpeername()}")
    response = {
        "status": True
    }
    try:
        is_logged_in(conn)
        is_result_valid(result)
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
        response["message"] = str(e)
    finally:
        conn.send(response, 153)
