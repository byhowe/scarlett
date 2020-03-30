#!/usr/bin/env python3
from importlib import import_module

from bson import ObjectId
from finian import Connection
from pymongo.database import Database

from scarlett.chatting import create_chat_from
from scarlett.logger import logger
from scarlett.scarlett import Scarlett


def create_main_chat(db: Database, user_id: ObjectId):
    squad_entry = db.get_collection("squads").find_one(
        {"title": "Main Chat"},
        {"_id": True}
    )
    if squad_entry is None:
        create_chat_from(db, user_id, "Main Chat")


def main():
    logger.debug("Initializing Scarlett...")
    scar = Scarlett()
    logger.info("Loading Scarlett modules...")
    with scar.conn_context():
        create_main_chat(scar.db, scar.user_id)
        logger.debug("Loading scarlett.loginmanager...")
        import_module("scarlett.loginmanager")
        logger.debug("Loading scarlett.chatter...")
        import_module("scarlett.chatter")

    @scar.new_connection
    def new_connection(conn: Connection):
        logger.info(f"New connection from {conn.socket.socket.getpeername()}.")

    @scar.connection_broke
    def connection_broke(conn: Connection):
        message = f"Disconnected from {conn.socket.socket.getpeername()}."
        if "username" in conn.session:
            message += "{" \
                       f"username={conn.session['username']}" \
                       "}"
        logger.info(message)

    logger.info("Listening for incoming connections...")
    scar.listen()


if __name__ == "__main__":
    main()
