from fastapi import Body, FastAPI

app = FastAPI(title="Mock NMS Northbound Interface")

ALARMS = [
    {"id": "a1", "device": "router-1", "severity": "critical", "text": "Link down"},
    {"id": "a2", "device": "switch-3", "severity": "minor", "text": "High temperature"},
]
DEVICES = [
    {"id": "router-1", "type": "router", "ip": "10.0.0.1"},
    {"id": "switch-3", "type": "switch", "ip": "10.0.0.3"},
]
PERFORMANCE = [{"device": "router-1", "cpu": 41.5, "mem": 62.0, "if_util": 17.3}]
CONFIG: dict = {"ntp": "10.0.0.250"}


@app.get("/alarms")
def alarms():
    return ALARMS


@app.get("/devices")
def devices():
    return DEVICES


@app.get("/performance")
def performance():
    return PERFORMANCE


@app.get("/config")
def get_config():
    return CONFIG


@app.put("/config")
def put_config(body: dict = Body(...)):
    CONFIG.update(body)
    return {"status": "applied", "config": CONFIG}
