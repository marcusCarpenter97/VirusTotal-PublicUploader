import os
import json
from pprint import pprint

sorted_sandbox = {}

batches = ["behaveVS_383", "behaveVS_388", "behaveVS_389"]

for batch in batches:
    reports = os.listdir(batch)

    for res_idx, report in enumerate(reports):
        print(f"{res_idx} / {len(reports)}", end="\r")
        path = os.path.join(batch, report)
        with open(path) as j_file:
            results = json.load(j_file)

        for result in results["data"]:
            pprint(result["attributes"]["sandbox_name"])
            pprint(result["attributes"])
            break
    raise SystemExit

    print(batch, "OK!")

"""
M2E0MGI5OWMwMDhlMjQwMmJiOTc4Njk5MmVkOGIyNTY6MTYyMzAyMDY5OA==   empty
M2E0MWE1N2VjZmZjZGFjNjIyM2UzMGY3MDI5ODBkMDU6MTYyMzM0NTMwNg==   empty
M2E0NDdjZmFhMWFiMjgxZjZiMmE4YThlMjcxYTE5MTE6MTYyMjk3MTY1NA==
M2E0NDE2ZjU1MTg1YzdiMWNmYWQ5NjRkYWQ4MzE3Yjc6MTYyMzIyNjg0OA==
M2E0NjUxZjY2ZjUwMzJmYWNlZWQ5ZDBmZWUyOGQ1MjQ6MTYyMjk1MTA3Ng==
M2E0NmNjZjY4N2FiZmFiYjkyNThmMDQ5NzgzZGVmZmY6MTYyMzY3NDM0NA==
M2E0NmZlZWYxMjQ0ZjY3OTNiODk3OGQ2ZDM3MjkzOWY6MTYyMzc0NTI5MA==
M2E0NzVkM2ZkMzI0MjM3YWM5ZDUxZDI3OWZkMTRmNDE6MTYyMzIyNjc0Ng==
M2E0NzYwZDVmNGU4ZmY4MGE4NDQyMzQ5YmUxYzIwN2I6MTYyMzY5OTU3Mw==
M2E0OGNhYjRlMjE2N2IxMzUxOWNhYmM5YjJjYTg5NzI6MTYyMzIxNzgwNw==
"""
