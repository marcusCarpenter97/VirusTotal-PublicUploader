import os
import json
import virustotal3.core as vt

def load_api_key(key_file: str) -> str:
    with open(key_file, "r") as api_file:
        api_key = api_file.readline()
    return api_key.strip("\n")

if __name__ == "__main__":
    analyses_dir = "benign-reports"
    result_dir = "benign_info"
    api_key_loc = "API-key.txt"

    api_key = load_api_key(api_key_loc)
    vt_file = vt.Files(api_key)

    analysis_ids = os.listdir(analyses_dir)

    for an_id in analysis_ids:
        print(f"Downloading behavioural report for: {an_id}")
        path = os.path.join(analyses_dir, an_id)

        with open(path, "r") as js:
            data = json.load(js)

        curr_hash = data["meta"]["file_info"]["sha256"]

        #res = vt_file.get_relationship(curr_hash, "behaviours")
        res = vt_file.info_file(curr_hash)

        save_path = os.path.join(result_dir, f"{an_id}")
        with open(save_path, "w") as j_report:
            json.dump(res, j_report, indent=4)
