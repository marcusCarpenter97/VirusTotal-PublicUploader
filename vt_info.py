import os
import json
import pathlib
import logging
import pandas as pd
from pprint import pprint
import virustotal3.core as vt
import virustotal3.errors

def load_api_key(key_file: str) -> str:
    with open(key_file, "r") as api_file:
        api_key = api_file.readline()
    return api_key.strip("\n")

VirusTotalApiError = virustotal3.errors.VirusTotalApiError

logging.basicConfig(filename="vt_info_logging.log", format="%(asctime)s %(name)s %(levelname)s: %(message)s", level=logging.DEBUG)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s"))
logging.getLogger().addHandler(console)

api_key_loc = "API-key.txt"
analyses_dir = "analyses"
api_key = load_api_key(api_key_loc)
vt_file = vt.Files(api_key)

dir_name = input("Enter path to source directory: ")

curr_dir = os.path.dirname(os.path.abspath(__file__))
new_dir = os.path.join(curr_dir, dir_name.strip("../"))
pathlib.Path(new_dir).mkdir(parents=True, exist_ok=True)

all_analyses = pd.DataFrame(os.listdir(analyses_dir), columns=["analysis id"])
all_hashes = pd.DataFrame(os.listdir(dir_name), columns=["sample"])
submitted_files = pd.read_csv("submitted_files.csv")

selected_analyses = submitted_files.loc[submitted_files["sample"].isin(all_hashes["sample"])]["analysis id"]

existing_results = pd.DataFrame(os.listdir(new_dir), columns=["analysis id"])

total_size = len(selected_analyses)
existing_size = len(existing_results)

selected_analyses = selected_analyses.loc[~selected_analyses.isin(existing_results["analysis id"])]

for idx, curr_id in enumerate(selected_analyses.values):
    logging.info(f"{idx+existing_size}/{total_size} : {curr_id}")
    path = os.path.join(analyses_dir, curr_id)

    with open(path, "r") as js:
        data = json.load(js)

    curr_hash = data["meta"]["file_info"]["sha256"]

    try:
        res = vt_file.info_file(curr_hash)
    except VirusTotalApiError as VTerr:
        logging.critical(VTerr)
        raise SystemExit from VTerr

    save_path = os.path.join(new_dir, curr_id)
    with open(save_path, "w") as j_report:
        json.dump(res, j_report, indent=4)
