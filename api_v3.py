
""" Simple script to interract with VirusTotal Public APIv3. """

import json
import virustotal3.core as vt
import virustotal3.errors
from time import sleep
from os import listdir
from os.path import isfile, join

VirusTotalApiError = virustotal3.errors.VirusTotalApiError

def load_api_key(key_file: str) -> str:
    with open(key_file, "r") as api_file:
        api_key = api_file.readline()
    return api_key.strip("\n")

def save_scan(saved_ids: str, result_dir: str, analysis_id: str, analysis: dict) -> None:
    # Save analysis id.
    with open(saved_ids, 'a') as si:
        si.write(f"{analysis_id}\n")

    # Save analysis result.
    analysis_md5 = analysis["meta"]["file_info"]["md5"]
    analysis_path = join(result_dir, f"{analysis_md5}.json")
    with open(analysis_path, 'w') as analysis_json:
        json.dump(analysis, analysis_json)

def log_error(e_filename: str, msg: VirusTotalApiError) -> None:
    with open(e_filename, 'a') as err_file:
        err_file.write(f"{msg}\n")

if __name__ == "__main__":
    TARGET_DIR = "target"
    API_KEY = "API-key.txt"
    ERROR_LOG = "error-log.txt"
    SAVED_IDS = "analysis-ids.txt"
    RESULT_DIR = "results"

    # Load API key and setup VirusTotal.
    api_key = load_api_key(API_KEY)
    vt_file = vt.Files(api_key)

    # Select all files from TARGET_DIR. This guarantees that all paths are files.
    # As listdir does not guarantee order the filenames are sorted for when the programme
    # continues the next day after the daily limit is reached.
    filenames = [join(TARGET_DIR, f_name) for f_name in listdir(TARGET_DIR) if isfile(join(TARGET_DIR, f_name))]
    filenames.sort()

    # To keep track of completed submissions the number of analysis
    # in SAVED_IDS is used as an index for the filenames.
    if isfile(SAVED_IDS):
        with open(SAVED_IDS, 'r') as save_file:
            line_count = len(save_file.readlines())
        filenames = filenames[line_count:]

    # Submit files for analysis.
    for filename in filenames:
        try:
            ret = vt_file.upload(filename)
        except VirusTotalApiError as VTerr:
            log_error(ERROR_LOG, VTerr)
            exit(0)

        sleep(15)  # The API only supports 4 requests every 1 minute.
        analysis_id = ret["data"]["id"]
        analysis = vt.get_analysis(api_key, analysis_id)
        save_scan(SAVED_IDS, RESULT_DIR, analysis_id, analysis)

