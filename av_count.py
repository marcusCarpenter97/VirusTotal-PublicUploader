import os
import json
import pandas as pd

def rank_av_from_vt_results(res_files):
    av_table = {}
    for idx, res_file in enumerate(res_files):
        with open(res_file, "r") as j_file:
            res_data = json.load(j_file)
        av_data = res_data["data"]["attributes"]["results"]
        print(idx, res_file, len(av_data.keys()))
    return av_table

source_dir = input("Enter source directory: ")

source_files = pd.Series(os.listdir(source_dir))

all_submissions = pd.read_csv("submitted_files.csv", index_col="sample")

selected_submissions = all_submissions.loc[source_files]

anal_ids = list(selected_submissions["analysis id"])

anal_paths = [os.path.join("analyses", anal_id) for anal_id in anal_ids]

rank = pd.DataFrame(rank_av_from_vt_results(anal_paths)).T

rank.to_csv(f"{source_dir[3:]}.csv")
