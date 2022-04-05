import csv
import requests
import json
import base64
import sys
import argparse
import urllib3
from datetime import datetime
from datetime import timedelta


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JIRA_INSTALLATION = "jira.installation.com"
FIRST_STATE = "IMPLEMENTATION"
FINAL_STATE = "DONE"


def write_on_file(content):
    with open("output.csv", "w") as f:
        writer = csv.writer(f)
        writer.writerow(["Ticket", "start", "end", "diff"])
        writer.writerows(content)


def main(argv):
    p = argparse.ArgumentParser(
        description="Gets a set of completed stories and list them with their implementation time."
    )
    p.add_argument(
        "filter_id", help="Id of the filter that contains completed stories."
    )
    p.add_argument(
        "-u",
        dest="username",
        help="JIRA username. Needs to have read access to all tickets returned from the search filter.",
    )
    p.add_argument(
        "-p", dest="password", help="Password for the JIRA user to use for API calls."
    )
    p.add_argument(
        "-j",
        dest="jira_installation",
        help="JIRA instalation url (without protocol) to use for API calls.",
    )
    args = p.parse_args(argv)

    if len(argv) < 4:
        print("Use with -u <username> -p <password> <JIRA-filter-id>.")
        sys.exit(2)
    transition_times = get_transition_times(
        args.username, args.password, args.jira_installation, args.filter_id
    )
    write_on_file(transition_times)


def get_transition_times(
    username, password, url, filter, first_state=FIRST_STATE, final_state=FINAL_STATE
):
    encoded = bytes(f"{username}:{password}".encode("utf-8"))
    headers = {
        "Authorization": "Basic %s" % str(base64.b64encode(encoded), "utf-8"),
        "Content-Type": "application/json",
    }
    results = []

    start_at = 0
    max_results = 50
    while True:
        print("Getting tickets from JIRA... (%s)" % str(start_at + max_results))
        print("startAt: %s\nmaxResults: %s" % (str(start_at), str(max_results)))
        all_issues = requests.get(
            url=f"https://{url}/rest/api/2/search?jql=filter={filter}&fields=key&startAt={start_at}&maxResults={max_results}",
            headers=headers,
            verify=False,
        )
        if all_issues.status_code != 200:
            print(
                "Tried to get all isses for JIRA filter '"
                + filter
                + "' Status code returned: "
                + str(all_issues.status_code)
            )
            sys.exit(2)

        response = json.loads(all_issues.content)
        issues = response["issues"]
        if len(issues) == 0:
            break

        for issue in issues:
            issue_content = requests.get(
                url=issue["self"] + "?expand=changelog&fields=changelog",
                headers=headers,
                verify=False,
            )

            changelog = json.loads(issue_content.content)["changelog"]
            histories = changelog["histories"]

            start_time = None
            end_time = None
            diff_time = None
            quick_transition = True

            for history in histories:
                for item in history["items"]:
                    if item["field"] != "status":
                        continue
                    if item["toString"] == first_state:
                        timeTransitioned = datetime.strptime(
                            (history["created"]), "%Y-%m-%dT%H:%M:%S.%f%z"
                        )
                        quick_transition = False
                        if start_time is None or timeTransitioned > start_time:
                            start_time = timeTransitioned
                    elif item["toString"] == final_state:
                        timeTransitioned = datetime.strptime(
                            (history["created"]), "%Y-%m-%dT%H:%M:%S.%f%z"
                        )
                        if end_time is None or timeTransitioned > end_time:
                            end_time = timeTransitioned
            if quick_transition:
                start_time = end_time
            diff_time = end_time - start_time if end_time is not None and start_time is not None else None
            print(str(issue["key"]) + ";" + str(diff_time))
            results.append([issue["key"], start_time, end_time, diff_time])
        start_at += max_results
    return results


if __name__ == "__main__":
    main(sys.argv[1:])
