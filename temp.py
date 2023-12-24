import os
import json
import pandas as pd
import virustotal3.core as vt
import virustotal3.errors

def load_api_key(key_file: str) -> str:
    with open(key_file, "r") as api_file:
        api_key = api_file.readline()
    return api_key.strip("\n")

api_key_loc = "API-key.txt"

saved_analyses = "analyses"

anal_list = ["ZTJhMDE4ZTE4OWIzNjAwZDBhYTNkNGY2NDA3N2E0ZTQ6MTYxOTk0Mzc1Mw==",
             "Y2FjYmI5NjA5NTU2MzY3ZTVmMWI0MmMwMTIzYWJjOGE6MTYxOTk0MzgxNA==",
             "OGU1YTgwOWE1MjU1OWZlODY3YWQyM2ExMGZkY2UzOWY6MTYxOTk0Mzc1MA==",
             "ODBhN2FhOTZkOTNjZmY2MzBlOWNiZmI5NDQwNjU2N2M6MTYxOTk0MzgwOA==", 
             "NzQ3MWUwMTkxOTExNDU5NDhlYzNjNDI5OTc3YWE5MjQ6MTYxOTk0MzgxMg==",
             "NWUxNjE1MWU4Njc2NWUzNGNhYTI2MzgyZDFkZDgzYzc6MTYxOTk0MzgxMA==", 
             "NWEwNzIxOGRhZTM5N2M1Y2ZhMGZiYTI4OWJiMDA4NmI6MTYxOTk0MzgwNQ==",
             "NTMxOGQyNmNiNWQzYjA0M2I3MWQ4ZTQ1YjlkMzIxM2M6MTYxOTk0Mzc0NA==",
             "NmU4MDZlNzI1MzM5NTBlY2ZhMGVlODIxZmFlMjM3ZDQ6MTYxOTk0Mzc0Mg==",
             "NjliODgxN2ZhZDUxYjcxODVhMGUxYTc1OGQ3MTE0ZTc6MTYxOTk0Mzc0OA==",
             "M2U4M2FmZjNlMDg3ZDVlZmE4MGY2OWMwNTFhNjkzNjM6MTYxOTk0Mzc0Ng==",
             "M2JlNTRmNjliZDBiNTkyNjk0NzllZTczNGYxNzg4M2U6MTYxOTk0MzgwNw=="]

#analyses_files = os.listdir(analyses_dir)

api_key = load_api_key(api_key_loc)
vt_file = vt.Files(api_key)

for analysis in anal_list:
    results = virustotal3.core.get_analysis(api_key, analysis)
    result_path = os.path.join(saved_analyses, analysis)

    with open(result_path, "w") as rp:
        json.dump(results, rp, indent=4, sort_keys=True)
