#!/usr/bin/env python3
from importlib import import_module

from bson import ObjectId
from finian import Connection
from pymongo.database import Database

from scarlett.chatting import create_chat_from, accept_pending_squads
from scarlett.logger import logger
from scarlett.scarlett import Scarlett


def create_main_chat(db: Database, user_id: ObjectId, password):
    squad_entry = db.get_collection("squads").find_one(
        {"title": "Main Chat"},
        {"_id": True}
    )
    if squad_entry is None:
        squad_id = create_chat_from(db, user_id, "Main Chat")
        accept_pending_squads(db, user_id, password, add_as_participant=False)
    else:
        squad_id = squad_entry["_id"]
    return squad_id


def main():
    logger.debug("Initializing Scarlett...")
    scar = Scarlett()
    logger.info("Loading Scarlett modules...")
    scar.main_squad = create_main_chat(scar.db, scar.user_id, scar.args.key_pass.encode())
    with scar.conn_context():
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
