from bson import ObjectId
from finian import Result, Connection
from pymongo.database import Database

from scarlett.logger import logger


def is_result_valid(result: Result):
    if not result.json or result.encrypted:
        logger.warning("Result is encrypted or not in JSON format!")
        raise Exception("Result is encrypted or not in JSON format!")


def is_logged_in(conn: Connection):
    if "username" not in conn.session:
        logger.debug("User was not logged in.")
        raise Exception("You are not logged in!")


def is_member_valid(member_id: ObjectId, db: Database):
    member_entry = db.get_collection("members").find_one(
        {"_id": member_id},
        {"pending": True, "public_key": True}
    )
    if member_entry["pending"] or "public_key" not in member_entry:
        logger.debug("Membership is not valid.")
        raise Exception("Membership is not valid!")
