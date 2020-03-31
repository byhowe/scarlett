#!/usr/bin/env python3
import argparse
import os
import time
from typing import Optional

import finian
import pymongo
from bson import ObjectId
from finian import Connection

from .encryption import rsa
from .logger import logger

parser = argparse.ArgumentParser(prog="Scarlett")
parser.add_argument("--main-chat-title", type=str, dest="main_chat_title", default="Main Chat",
                    help="Title of the main chat squad.")
parser.add_argument("--key-pass", type=str, dest="key_pass",
                    help="Password to encrypt and decrypt the private key.")
parser.add_argument("--key-user", type=str, dest="key_user", default="keen",
                    help="Username to store the keys in.")
parser.add_argument("--host", type=str, default="127.0.0.1", dest="host",
                    help="The address server runs on.")
parser.add_argument("--port", type=int, default=5409, dest="port",
                    help="The port server runs on.")
parser.add_argument("--mongo-host", type=str, default="127.0.0.1",
                    dest="mongo_host",
                    help="The address MongoDB runs on.")
parser.add_argument("--mongo-port", type=int, default=5409,
                    dest="mongo_port", help="The port MongoDB runs on.")
parser.add_argument("--mongo-user", type=str, default=os.environ["USER"],
                    dest="mongo_user",
                    help="Username used to connect MongoDB.")
parser.add_argument("--mongo-pass", type=str, default=None, dest="mongo_pass",
                    help="Password used to connect MongoDB.")
parser.add_argument("--mongo-db", type=str, default="scarlett",
                    dest="mongo_db", help="Default database to be used.")
args = parser.parse_args()


class Scarlett(finian.Server):
    def __init__(self):
        self.args = args
        super().__init__(self.args.host, self.args.port)
        logger.info("Initializing RSA keys.")
        db = self.db
        user_entry = db.get_collection("members").find_one(
            {"username": args.key_user},
            {"_id": True, "private_key": True, "public_key": True}
        )
        if user_entry is None:
            public_key, private_key = rsa.generate_key_pair()
            self.user_id = db.get_collection("members").insert_one({
                "admin": True,
                "username": args.key_user,
                "pending": False,
                "squads": [],
                "pending_squads": [],
                "public_key": rsa.serialize_public_key(public_key),
                "private_key": rsa.serialize_private_key(private_key, args.key_pass.encode())
            }).inserted_id
            time.sleep(0.5)
        else:
            self.user_id = user_entry["_id"]
            public_key, private_key = (rsa.load_public_key(user_entry["public_key"]),
                                       rsa.load_private_key(user_entry["private_key"], args.key_pass.encode()))
        self.pubkey, self.privkey = public_key, private_key
        logger.info("RSA keys are initialized.")
        # key_dir = Path(args.key_dir)
        # if not key_dir.is_dir():
        #     logger.error("%s is not a directory!" % args.key_dir)
        #     raise Exception("%s is not a directory!" % args.key_dir)
        # for file in [x for x in key_dir.iterdir() if x.is_file()]:
        #     with file.open("rb") as f:
        #         logger.debug("Opened %s." % str(file.absolute()))
        #         key = f.read()
        #         if file.name == "pub":
        #             logger.info(
        #                 "Public key found in %s." % str(file.absolute()))
        #             self.pubkey = serialization.load_pem_public_key(
        #                 key,
        #                 backend=default_backend()
        #             )
        #         if file.name == "priv":
        #             logger.info(
        #                 "Private key found in %s." % str(file.absolute()))
        #             self.privkey = serialization.load_pem_private_key(
        #                 key,
        #                 password=None,
        #                 backend=default_backend()
        #             )
        # if self.pubkey is None or self.privkey is None:
        #     logger.debug("No keys were found.")
        #     logger.info("Generating RSA key pair.")
        #     privkey = rsa.generate_private_key(
        #         public_exponent=65537,
        #         key_size=4096,
        #         backend=default_backend()
        #     )
        #     self.pubkey = privkey.public_key()
        #     self.privkey = privkey
        #     logger.debug("RSA key pair is generated.")
        #     pub_file = key_dir / "pub.pem"
        #     priv_file = key_dir / "priv.pem"
        #     logger.info("Writing RSA keys in files.")
        #     with pub_file.open("wb") as f:
        #         logger.debug(
        #             "Writing public key in %s", str(pub_file.absolute()))
        #         f.write(self.pubkey)
        #     with priv_file.open("wb") as f:
        #         logger.debug(
        #             "Writing private key in %s", str(priv_file.absolute()))
        #         f.write(self.privkey)

    @property
    def db(self):
        logger.debug("Creating a new MongoClient.")
        return pymongo.MongoClient(
            host=self.args.mongo_host,
            port=self.args.mongo_port,
            username=self.args.mongo_user,
            password=self.args.mongo_pass
        ).get_database(self.args.mongo_db)

    def find_member(
            self, username: str = None,
            member_id: ObjectId = None
    ) -> Optional[Connection]:
        logger.debug(
            "Searching for an online user: {'username': %s, 'id': %s}" %
            (str(username), str(member_id))
        )
        for client in self.clients.copy():
            if (
                    username is not None and
                    "username" in client.session and
                    username == client.session["username"]
            ):
                return client
            elif (
                    member_id is not None and
                    "id" in client.session and
                    member_id == client.session["id"]
            ):
                return client
        logger.debug(
            "User is not online: {'username': %s, 'id': %s}" %
            (str(username), str(member_id))
        )
        return None
