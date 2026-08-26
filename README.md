# Mayhem

A third-party agent for the [Havoc](https://github.com/HavocFramework/Havoc) C2
framework, built for Talon.

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

## Layout

```
Mayhem/
├── handler.py           # service client + Mayhem agent definition
├── havoc/               # vendored Havoc python library (see below)
│   ├── agent.py
│   ├── service.py
│   └── externalc2.py
├── dependencies.sh      # environment bootstrap
├── requirements.txt     # dependencies
└── .env.example         # config template
```
