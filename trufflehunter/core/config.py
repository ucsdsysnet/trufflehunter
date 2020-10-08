import json
import os
def loadDefaultConfig():
    dirname, _ = os.path.split(os.path.abspath(__file__))
    with open("{}/config.json".format(dirname)) as f:
        data = json.load(f)
    return data

Config = loadDefaultConfig()
