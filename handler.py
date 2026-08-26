import os

from dotenv import load_dotenv

from havoc.agent import *
from havoc.service import HavocService

load_dotenv()


class Mayhem(AgentType):
    Name = "Mayhem"
    Author = "me1n + Hera + Cushz"
    Version = "0.1"
    Description = "3rd party agent created for Talon"
    MagicValue = 0x6D61796F   # 'mayo'
    Arch = ["x64"]
    Formats = [{"Name": "Windows Executable", "Extension": "exe"}]
    BuildingConfig = {"Sleep": "10"}
    Commands = []


def main():
    endpoint = os.environ.get("service_endpoint")
    password = os.environ.get("service_password")

    if not endpoint or not password:
        raise SystemExit(
            "[!] service_endpoint and service_password must be set.\n"
            "    Copy .env.example to .env and fill it in."
        )

    service = HavocService(endpoint=endpoint, password=password)
    service.register_agent(Mayhem())


if __name__ == '__main__':
    main()
