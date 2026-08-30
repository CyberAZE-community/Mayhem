# Mayhem

A third-party agent for the [Havoc](https://github.com/HavocFramework/Havoc) C2
framework

`handler.py` runs a service client that connects to a Havoc teamserver's
3rd-party service endpoint and registers the `Mayhem` agent type with it.

## Requirements

- Python **3.10+** (`dependencies.sh` installs 3.10; imports verified on 3.10 and 3.12)
- A running Havoc teamserver with a `[Service]` block in its `.yaotl` profile

## Setup

```bash
git clone <repo-url>
cd Mayhem

./dependencies.sh          # installs python3.10, creates venv, installs deps
source venv/bin/activate
```

Or manually:

```bash
python3.10 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Configuration

Copy `.env.example` to `.env` and fill in both values. They must match the
`[Service]` block of your teamserver profile:

```
service_endpoint=wss://127.0.0.1:40056/mayhem
service_password=<your service password>
```

`.env` is gitignored — **never commit it**.

## Running

Start the Havoc teamserver first, then:

```bash
source venv/bin/activate
python handler.py
```

The agent registers with the teamserver and stays connected. It will appear in
the Havoc client's payload builder as an available agent type.

## Agent

The C agent lives in `Agent/`. Cross-compile with mingw:

```bash
cd Agent
x86_64-w64-mingw32-gcc -o mayo.exe Main.c Command.c Package.c Transport.c -lwinhttp -liphlpapi
```

Update `CONFIG_HOST` and `CONFIG_PORT` in `Main.c` to point at the teamserver listener.

### Supported commands

| Command | ID | Description |
|---|---|---|
| shell | 0x152 | Execute a shell command via cmd.exe |
| upload | 0x153 | Upload a file to the target |
| download | 0x154 | Download a file from the target |
| proclist | 0x156 | List running processes (PID, PPID, name) |
| exit | 0x155 | Terminate the agent |

## Layout

```
Mayhem/
├── handler.py           # service client + Mayhem agent definition
├── havoc/               # vendored Havoc python library
│   ├── agent.py
│   ├── service.py
│   └── externalc2.py
├── Agent/               # C implant source
│   ├── Main.c           # entry point, config, register
│   ├── Command.c/h      # dispatch loop + command handlers
│   ├── Package.c/h      # packet serialization
│   ├── Transport.c/h    # WinHttp transport
│   └── CMakeLists.txt   # cmake build
├── dependencies.sh      # environment bootstrap
├── requirements.txt     # dependencies
└── .env.example         # config template
```
