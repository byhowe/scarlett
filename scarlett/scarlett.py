#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
from typing import Optional

import finian
import pymongo
import rsa
from bson import ObjectId
from finian import Connection

from .logger import logger

parser = argparse.ArgumentParser(prog="Scarlett")
parser.add_argument("--key-dir", type=str, default=".", dest="key_dir",
                    help="Path to the directory in which "
                         "the RSA keys will be stored.")
parser.add_argument("--host", type=str, default="127.0.0.1", dest="host",
                    help="The address server runs on.")
parser.add_argument("--port", type=int, default=5409, dest="port",
                    help="The port server runs on.")
parser.add_argument("--mongo-host", type=str, default="127.0.0.1",
                    dest="mongo_host",
                    help="The address MongoDB runs on.")
parser.add_argument("--mongo-port", type=str, default="5409",
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
        key_dir = Path(args.key_dir)
        logger.info("Initializing RSA keys.")
        if not key_dir.is_dir():
            logger.error("%s is not a directory!" % args.key_dir)
            raise Exception("%s is not a directory!" % args.key_dir)
        for file in [x for x in key_dir.iterdir() if x.is_file()]:
            with file.open("rb") as f:
                logger.debug("Opened %s." % str(file.absolute()))
                key = f.read()
                if file.name == "pub":
                    logger.info(
                        "Public key found in %s." % str(file.absolute()))
                    self.pubkey = rsa.key.PublicKey.load_pkcs1(key)
                if file.name == "priv":
                    logger.info(
                        "Private key found in %s." % str(file.absolute()))
                    self.privkey = rsa.key.PrivateKey.load_pkcs1(key)
        if self.pubkey is None or self.privkey is None:
            logger.debug("No keys were found.")
            logger.info("Generating RSA key pair.")
            self.pubkey, self.privkey = rsa.newkeys(4096)
            logger.debug("RSA key pair is generated.")
            pub_file = key_dir / "pub"
            priv_file = key_dir / "priv"
            logger.info("Writing RSA keys in files.")
            with pub_file.open("wb") as f:
                logger.debug(
                    "Writing public key in %s", str(pub_file.absolute()))
                f.write(self.pubkey)
            with priv_file.open("wb") as f:
                logger.debug(
                    "Writing private key in %s", str(priv_file.absolute()))
                f.write(self.privkey)
        logger.info("RSA keys are initialized.")

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
        for client in self.clients:
            if (
                    "username" in client.session and
                    username == client.session["username"]
            ):
                return client
            elif (
                    "id" in client.session and
                    member_id == client.session["id"]
            ):
                return client
        logger.debug(
            "User is not online: {'username': %s, 'id': %s}" %
            (str(username), str(member_id))
        )
        return None
