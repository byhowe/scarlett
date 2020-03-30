from datetime import datetime

import zila
from bson import ObjectId
from passlib.handlers.pbkdf2 import pbkdf2_sha512
from pymongo.database import Database

from scarlett.encryption import fernet, rsa
from scarlett.logger import logger
from scarlett.validators import is_member_valid


def create_chat_from(db: Database, user_id: ObjectId, title: str = None, participant_id: ObjectId = None):
    if title is not None and len(zila.validate(title, [zila.Length(max_length=50)])) > 0:
        logger.debug("User inputs do not meet the requirements.")
        raise Exception("Title cannot be more than 50 characters long!")
    logger.debug("Generating a new squad password.")
    squad_pass = fernet.generate_key()
    post = {
        "timestamp": datetime.utcnow(),
        "participants": [user_id],
        "key": pbkdf2_sha512.hash(squad_pass)
    }
    if title is None:
        post["participants"].append(participant_id)
        post['contact'] = True
    else:
        post['title'] = title
        post['contact'] = False
    squad_id = db.get_collection("squads").insert_one(post).inserted_id
    add_member_to_chat(db, user_id, squad_id, password=squad_pass)
    logger.info("A new squad has been created: {"
                f"title={title}, id={str(squad_id)}"
                "}")


def add_member_to_chat(db: Database,
                       member_id: ObjectId,
                       squad_id: ObjectId,
                       password: bytes = None,
                       alpha_id: ObjectId = None,
                       alpha_password: bytes = None):
    squad_entry = db.get_collection("squads").find_one(
        {"_id": squad_id},
        {"_id": True}
    )
    if squad_entry is None:
        logger.debug("Squad does not exist: {"
                     f"id={str(squad_id)}"
                     "}")
        raise Exception("This squad does not exist!")
    # if member_id not in squad_entry["leaders"]:
    #     logger.debug(f"User {username} tried to access"
    #                  " without authorization.")
    #     raise Exception("You are not authorized!")
    member_entry = db.get_collection("members").find_one(
        {"_id": member_id,
         "squads": True, "pending_squads": True})
    if member_entry is None:
        logger.debug(f"Member does not exist.")
        raise Exception("Member does not exist!")
    is_member_valid(member_id, db)
    for squad in (
            member_entry["squads"] +
            member_entry["pending_squads"]
    ):
        if squad["id"] == squad_id:
            logger.debug(
                f"Member is already present in the squad")
            raise Exception(
                "This member is already present in the squad!")
    if password is None:
        is_member_valid(alpha_id, db)
        alpha_entry = db.get_collection("members").find_one(
            {"_id": alpha_id},
            {"squads": True, "private_key": True}
        )
        if alpha_entry is None:
            logger.debug("Alpha doesn't exist.")
            raise Exception("Alpha doesn't exist!")
        squad_entry = None
        for squad in alpha_entry["squads"]:
            if squad["id"] == squad_id:
                squad_entry = squad
                break
        if squad_entry is None:
            logger.debug("Alpha is not in the squad.")
            raise Exception("Alpha is not in the squad!")
        alpha_private_key = rsa.load_private_key(alpha_entry["private_key"], alpha_password)
        password = rsa.decrypt(alpha_private_key, squad_entry["key"])

    pem_public_key = db.get_collection("members").find_one(
        {"_id": member_id},
        {"public_key": True}
    )["public_key"]
    member_public_key = rsa.load_public_key(pem_public_key)
    db.get_collection("member").update_one(
        {"_id": member_id},
        {"$push": {"pending_squads": {
            "id": squad_id,
            "key": rsa.encrypt(member_public_key, password)
        }}}
    )
