import os
import json
import pandas as pd

def add_res_to_av_table(av_table, av_name, res_type):
    try:
        av_table[av_name][res_type] += 1
    except KeyError:
        if av_name in av_table:
            av_table[av_name][res_type] = 1
        else:
            av_table[av_name] = {res_type : 1}

def rank_av_from_vt_results(res_files):
    av_table = {}
    for idx, res_file in enumerate(res_files):
        print(idx)
        with open(res_file, "r") as j_file:
            res_data = json.load(j_file)
        av_data = res_data["data"]["attributes"]["results"]
        for av_name in av_data:
            add_res_to_av_table(av_table, av_name, av_data[av_name]["category"])
    return av_table

source_dir = input("Enter source directory: ")

source_files = pd.Series(os.listdir(source_dir))

all_submissions = pd.read_csv("submitted_files.csv", index_col="sample")

selected_submissions = all_submissions.loc[source_files]

anal_ids = list(selected_submissions["analysis id"])

anal_paths = [os.path.join("analyses", anal_id) for anal_id in anal_ids]

rank = pd.DataFrame(rank_av_from_vt_results(anal_paths)).T

rank.to_csv(f"{source_dir[3:]}.csv")

