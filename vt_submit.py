import os
import csv
import time
import json
import logging
import pandas as pd
import virustotal3.core as vt
import virustotal3.errors

def load_api_key(key_file: str) -> str:
    with open(key_file, "r") as api_file:
        api_key = api_file.readline()
    return api_key.strip("\n")

def check_progress(submitted_files: str, completed_analysis: str, column: str) -> list:
    """
    column: Must be one of the follwoing three options: 'sample', 'analysis id', 'md5'
    """
    result_rows = []
    if os.path.isfile(submitted_files):
        with open(submitted_files, "r", newline="") as sf:
            reader = csv.DictReader(sf)
            for row in reader:
                result_rows.append(row[column])
    else:
        logging.warning(f"{submitted_files} could not be found. Creating a new one.")
        with open(submitted_files, "w", newline="") as sf:
            fieldnames = ['sample', 'analysis id']
            writer = csv.DictWriter(sf, fieldnames=fieldnames)
            writer.writeheader()
        with open(completed_analysis, "w", newline="") as ca:
            fieldnames = ['analysis id', 'sha256']
            writer = csv.DictWriter(ca, fieldnames=fieldnames)
            writer.writeheader()
    return result_rows

if __name__ == "__main__":

    VirusTotalApiError = virustotal3.errors.VirusTotalApiError

    logging.basicConfig(filename="logging.log", format="%(asctime)s %(name)s %(levelname)s: %(message)s", level=logging.DEBUG)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s"))
    logging.getLogger().addHandler(console)

    samples_dir = "samples"
    submitted_files = "submitted_files.csv"
    completed_analysis = "completed_analysis.csv"
    saved_analyses = "analyses"
    api_key_loc = "API-key.txt"

    api_key = load_api_key(api_key_loc)
    vt_file = vt.Files(api_key)

    try:
        samples = os.listdir(samples_dir)
    except FileNotFoundError as fnfe:
        logging.critical(f"Could not list files in {samples_dir}.")
        raise SystemExit from fnfe

    submitted = check_progress(submitted_files, completed_analysis, "sample")

    submissions = list(set(samples) - set(submitted))

    logging.info(f"Number of files found: {len(samples)}")
    logging.info(f"Number of completed submissions: {len(submitted)}")
    logging.info(f"Number of submissions: {len(submissions)}")

    if not submissions:
        logging.critical("There is nothing to submit becasue the submission queue is empty.")
        raise SystemExit

    for submission in submissions:
        submission_path = os.path.join(samples_dir, submission)
        logging.info(f"Submitting {submission} to VirusTotal for analysis.")
        try:
            ret = vt_file.upload(submission_path)
        except VirusTotalApiError as VTerr:
            logging.critical(VTerr)
            raise SystemExit from VTerr

        analysis_id = ret["data"]["id"]
        try:
            with open(submitted_files, "a", newline="") as sf:
                progress_logger = csv.writer(sf)
                progress_logger.writerow([submission, analysis_id])
        except FileNotFoundError as fnfe:
            logging.warning(f"{submitted_files} could not be opened for writing. Progress was not saved because {submission}"
                           f"could not be recorded as processed.")
            raise SystemExit from fnfe

        time.sleep(1)

    logging.info("Finished submitting files.")

    submitted = check_progress(submitted_files, completed_analysis, "analysis id")

    try:
        analysed = os.listdir(saved_analyses)
    except FileNotFoundError as fnfe:
        logging.critical(f"Could not list files in {saved_analyses}.")
        raise SystemExit from fnfe

    analyses = list(set(submitted) - set(analysed))

    logging.info(f"Number of completed submissions: {len(submitted)}")
    logging.info(f"Number of completed analysis: {len(analysed)}")
    logging.info(f"Number of analysis to complete: {len(analyses)}")

    for analysis in analyses:
        logging.info(f"Requesting analysis for {analysis}")
        results = virustotal3.core.get_analysis(api_key, analysis)
        status = results["data"]["attributes"]["status"]

        while "completed" not in status:
            results = virustotal3.core.get_analysis(api_key, analysis)
            status = results["data"]["attributes"]["status"]
            logging.info(f"Current status for {analysis} is {status}")
            time.sleep(10)

        sha256 = results["meta"]["file_info"]["sha256"]
        result_path = os.path.join(saved_analyses, sha256)
        with open(result_path, "w") as rp:
            json.dump(results, rp, indent=4, sort_keys=True)

        with open(completed_analysis, "a", newline="") as ca:
            progress_logger = csv.writer(ca)
            progress_logger.writerow([analysis, sha256])

        time.sleep(1)

    logging.info("Finished requesting analyses.")

    df1 = pd.read_csv(submitted_files)
    df2 = pd.read_csv(completed_analysis)
    df3 = df1.merge(df2)
    df3.to_csv("progress.csv", index=False)
