# -*- coding: utf-8 -*-
# __version__ = '0.9'

from __future__ import print_function
import logging
import os
import errno
try:
    # for python 3
    import urllib.request as urllib_request
except ImportError:
    # for python 2
    import urllib2 as urllib_request
import json
import time
import re
import datetime
import argparse
from truffleHog import truffleHog
from json2html import *
import csv
from scripts.bitbucket import Bitbucket
from git import Repo, GitCommandError
import multiprocessing as mp

# Set global 'utf8' support
reload(sys)
sys.setdefaultencoding('utf8')


try:
    # for python 2
    import ConfigParser as configparser
except ImportError:
    # for python 3
    import configparser

# General logging configuration
log_file_time = time.strftime("%Y-%m-%d-%H-%M", time.gmtime())
log_file_name = "logs/" + log_file_time + "-bitbucket-checker.log"
logfile = os.path.realpath(os.path.join(os.path.dirname(__file__), log_file_name))
print('All logs are stored in file - {0}'.format(logfile))

# create logger with 'spam_application'
logger = logging.getLogger('creds-checker')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
fh = logging.FileHandler(logfile)
fh.setLevel(logging.DEBUG)

# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s')
fh.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(fh)

CONFIG = configparser.ConfigParser()
CONFIG.read('.config/config.cfg')


def datetime_handler(x):
    """
    For for EC2 datetime.datetime() value handling
    :param x:
    :return: string
    """
    if isinstance(x, datetime):
        return x.isoformat()
    raise TypeError("Unknown type")


def createDirs():
    """
    Create program working dirs
    :return: none
    """
    # Create directories
    directories = ['tmp', 'logs', 'repos', 'backup', '.config', 'results', 'checks', 'stats']
    for directory in directories:
        try:
            os.makedirs(directory)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise


def write_to_file(filename, directory, data):
    """
    Func for store json formatted data to local file
    :param filename: string
    :param directory: string
    :param data: dictionary
    :return: string
    """
    if not os.path.isdir(directory):
        os.makedirs(directory)
    filename = directory + '/' + log_file_time + "-" + filename
    outfile = open(filename, 'w')
    outfile.write(data)
    outfile.close()
    return filename


def write_json_to_file(filename, directory, data, time=True):
    """
    Func for store json formatted data to local file
    :param filename: string
    :param directory: string
    :param data: dictionary
    :param time: boolean
    :return: None
    """
    if not os.path.isdir(directory):
        os.makedirs(directory)
    if time:
        filename = directory + '/' + log_file_time + "-" + filename
    else:
        filename = directory + '/' + filename
    json_outfile = open(filename, 'w')
    json.dump(data, json_outfile, default=datetime_handler)
    json_outfile.close()
    return filename


def read_json_file(path):
    """
    Func for store json formatted data to local file
    :param path: string
    :return: none
    """
    try:
        return json.loads(open(path).read())
    except IOError:
        print("File is missed. Please check")


def json2csvFile(filename, directory, json_input, header):
    """
    Convert JSON to CSV
    :param filename: string
    :param directory: string
    :param json_input: boolean
    :param header: list
    :return: string
    """
    file_path = directory + "/" + log_file_time + "-" + filename
    # Create header for CSV document
    columns = []
    if header and type(header) == list:
        columns = header
    elif not header:
        if type(json_input) == list:
            columns = sorted(json_input[0].keys())
        elif type(json_input) == dict:
            columns = sorted(json_input.keys())
            json_input = [json_input]

    with open(file_path, 'wb') as csvF:
        csv.register_dialect('escaped', escapechar='\\', quotechar="\"", doublequote=True,
                             quoting=csv.QUOTE_ALL, delimiter=',', skipinitialspace=True)

        csv_writer = csv.DictWriter(csvF, fieldnames=columns, dialect='escaped')
        csv_writer.writeheader()
        for issue in json_input:
            csv_writer.writerow(issue)
    return file_path


def get_repos_uri(bb_session, owner, pagination):
    """
    Get repository URI
    :param bb_session:  urllib http object
    :param owner: string
    :param pagination: boolean
    :return: list
    """
    success, repo = bb_session.repository.all(owner=owner, pagination=pagination)
    return success, repo


def getRepositoriesURI(response):
    """
    Get repositories URIs
    :param response: dictionary
    :return: list
    """
    git_uris = []
    for page in response.keys():
        for value in response[page]['values']:
            git_uris.append(value['links']['clone'][0]['href'])
    return sorted(git_uris)


def prepareReposToJson(json_repos):
    """
    Convert information about repo to proper format
    :param json_repos:
    :return: dictionary
    """
    columns = ["created_on", "description", "fork_policy", "full_name", "has_issues", "has_wiki", "is_private",
               "language", "links", "mainbranch", "name", "owner", "project", "scm", "size", "slug", "type",
               "updated_on", "uuid", "website"]
    repos = {}
    for page in json_repos.keys():
        for value in json_repos[page]['values']:
            new_value = {col: value[col] for col in columns}
            new_value['links'] = value['links']['html']['href']
            new_value['project_link'] = value['project']['links']['html']['href']
            new_value['project'] = value['project']['key']
            new_value['project_name'] = value['project']['name']
            new_value['owner_link'] = value['owner']['links']['html']['href']
            new_value['owner'] = value['owner']['username']
            clone_link = 'https://' + re.findall('^https://\S+@(.*)$', value['links']['clone'][0]['href'])[0]
            repos[clone_link] = new_value.copy()
    return repos


def formBitbucketReposLists(bb_session, owner):
    """
    Get Bitbucket repositories list
    :param bb_session: http authenticated session
    :param owner: string
    :return: dictionary
    """
    # Get all repositories
    success, repositories = get_repos_uri(bb_session, owner, pagination=True)
    json_file = write_json_to_file('all_repositories.json', 'tmp', repositories, True)
    repos_json = prepareReposToJson(repositories)
    json_formatted_file = write_json_to_file('formatted_repositories.json', 'tmp', repos_json, True)
    json2csvFile('all_repositories.csv', 'tmp', repos_json.values(), False)
    logger.info('Repositories were exported to JSON file - {0}'.format(json_file))
    logger.info('Repositories were exported to CSV file - {0}'.format(json_formatted_file))
    return repos_json


def clone_git_repo(git_auth_url, git_url, json_repos, count, not_clone):
    """
    Clone or fetch bitbucket repository
    :param git_auth_url: string
    :param git_url: string
    :param json_repos: dictionary
    :param count: integer
    :param not_clone: boolean
    :return: string
    """
    project_path = os.getcwd() + "/repos/" + json_repos[git_url]["slug"]
    project_git_path = project_path + "/.git"
    git_slug = git_url.split('/')[-1]
    # Clone repository or fetch new commits
    if os.path.exists(project_git_path):
        logger.info('Rep #{0}. Dir .git dit exists and started to pull Bitbucket repo: {1}'.format(count, git_slug))
        repo = Repo(project_git_path)
        if not not_clone:
            repo.remote().pull()
        logger.info('Rep #{0}. Successfully Fetched Bitbucket repo: {1}'.format(count, git_slug))
    elif not os.path.exists(project_path):
        os.makedirs(project_path)
        logger.info('Rep #{0}. Created dir and started to clone Bitbucket repo: {1}'.format(count, git_slug))
        Repo.clone_from(git_auth_url, project_path)
        logger.info('Rep #{0}. Successfully Cloned Bitbucket repo: {1}'.format(count, git_slug))
    elif not os.path.exists(project_git_path):
        logger.info('Rep#{0} Dir exists and started to clone Bitbucket repo: {1}'.format(count, git_slug))
        Repo.clone_from(git_auth_url, project_path)
        logger.info('Rep#{0} Successfully Cloned Bitbucket repo: {1}'.format(count, git_slug))

    return project_path


def combine_all_checks(output_csv, output_html):
    """
    Save all findings in files with different format
    :param output_csv: boolean
    :param output_html: boolean
    :return: string, dictionary
    """
    check_dir = os.path.realpath(os.path.dirname(__file__) + "/checks")
    check_files = [os.path.join(check_dir, f) for f in os.listdir(check_dir)
                   if os.path.isfile(os.path.join(check_dir, f))]
    if not check_files:
        print('No file with fidnings found. Run script without arg: "--report" first')
        exit(0)
    found_leaks = []
    header = ["branch", "type", "reason", "stringsFound", "diff", "language", "commit", "gitSlug", "gitUrl", "author",
              "commitHash", "audit_date", "commit_date", "stringsFound", "path", "project", "projectName"]
    for check in sorted(check_files):
        output = read_json_file(check)
        found_leaks.extend(output)

    # Save results in different formats
    if output_html:
        found_leaks_html = json2html.convert(json=found_leaks, encode=True, escape=True)
        write_to_file('found-leaks.html', 'results', found_leaks_html)
    if output_csv:
        csv_file = json2csvFile('found-leaks.csv', 'results', found_leaks, header)
        realpath = os.path.realpath(os.path.join(os.path.dirname(__file__), "/results/"))
        csv_final_file = realpath + csv_file
        return csv_final_file, found_leaks
    return False, found_leaks


def count_reason_stats(json_file):
    """
    Count stats for found leaks in Company repositories
    :param json_file:
    :return: none
    """
    # Count statistic for all findings
    reason_count = {}
    for leak in json_file:
        # General stats
        if leak['reason'] not in reason_count.keys():
            reason_count[leak['reason']] = 0
        reason_count[leak['reason']] += 1

    reason_stats = []
    header = ["project", "count"]
    for k, v in reason_count.iteritems():
        stats = {header[0]: k, header[1]: v}
        reason_stats.append(stats.copy())

    json2csvFile('reason_stats.csv', 'stats', reason_stats, False)
    write_json_to_file('reason_stats.json', 'stats', reason_stats, True)


def count_project_stats(json_file):
    """
    Count stats for found leaks in Company repositories
    :param json_file:
    :return: none
    """
    # Count statistic for all findings
    project_count = {}
    for leak in json_file:
        # Project stats
        if leak['project'] not in project_count.keys():
            project_count[leak['project']] = {}
        if leak['reason'] not in project_count[leak['project']].keys():
            project_count[leak['project']][leak['reason']] = 0
        project_count[leak['project']][leak['reason']] += 1

    project_stats = []
    header = ["project", "reason", "count"]
    for proj, reasons in project_count.iteritems():
        for reason, count in reasons.iteritems():
            stats = {header[0]: proj, header[1]: reason, header[2]: count}
            project_stats.append(stats.copy())

    json2csvFile('project_stats.csv', 'stats', project_stats, False)
    write_json_to_file('project_stats.json', 'stats', project_stats, True)


def count_repo_stats(json_file):
    """
    Count stats for found leaks in Company repositories
    :param json_file:
    :return: none
    """
    # Count statistic for all findings
    repo_count = {}
    for leak in json_file:
        # Repository stats
        if leak['project'] not in repo_count.keys():
            repo_count[leak['project']] = {}
        if leak['gitSlug'] not in repo_count[leak['project']].keys():
            repo_count[leak['project']][leak['gitSlug']] = {}
        if leak['reason'] not in repo_count[leak['project']][leak['gitSlug']].keys():
            repo_count[leak['project']][leak['gitSlug']][leak['reason']] = 0
        repo_count[leak['project']][leak['gitSlug']][leak['reason']] += 1

    repo_stats = []
    header = ["project", "repository", "reason", "count"]
    for project, repositories in repo_count.iteritems():
        for repo, reasons in repositories.iteritems():
            for reason, count in reasons.iteritems():
                stats = {header[0]: project, header[1]: repo, header[2]: reason, header[3]: count}
                repo_stats.append(stats.copy())

    json2csvFile('repo_stats.csv', 'stats', repo_stats, False)
    write_json_to_file('repo_stats.json', 'stats', repo_stats, True)
    exit(0)


def search_bitbucket(count, git_urls, username, secret, args, json_repos, total_rep):

    git_url = git_urls[count]
    try:
        git_slug = git_url.split('/')[-1][:-4]
        git_auth_url = git_url.replace('https://', 'https://' + username + ':' + secret + '@')
        do_entropy = truffleHog.str2bool(args.do_entropy)

        project_path = clone_git_repo(git_auth_url, git_url, json_repos, count, args.not_clone)
        logger.info('Rep #{0}. Starting to verify Bitbucket repo #{1} from {2} {3}'.format(count,
                                                                                           count,
                                                                                           total_rep,
                                                                                           git_slug))
        # Search sensitive data using regexChecks.regexes_txt in folder: truffleHog
        found_leaks = truffleHog.find_strings(project_path, git_url, json_repos, args.since_commit,
                                              args.max_depth, args.do_regex, do_entropy)
        fount_leaks_file = str(count) + "-code-" + git_slug + ".json"
        if found_leaks:
            write_json_to_file(fount_leaks_file, 'checks', found_leaks, False)

        # Search sensitive data using regexChecks.regexes_fs in folder: truffleHog
        found_fs_leaks = truffleHog.searchSensitiveFilesInRepo(project_path, git_url, json_repos)
        fs_file = str(count) + "-fs-" + git_slug + ".json"
        if found_fs_leaks:
            write_json_to_file(fs_file, 'checks', found_fs_leaks, False)
        logger.info('Rep #{0}. Successfully Verified Bitbucket repo #{1} from {2} {3}\n'.format(count,
                                                                                                count,
                                                                                                total_rep,
                                                                                                git_slug))
        print("Repo#", count, ". Slug. ", git_slug)
        count += 1
    except GitCommandError as exception:
        logger.info('Rep #{0}. Exception in parsing repo {1}. Details are - {2}'.format(count,
                                                                                        git_slug,
                                                                                        str(exception)))


def main():
    """
    Main func for Bitbucket sensitive data scanner tool
    :return: none
    """
    parser = argparse.ArgumentParser(description='Find secrets hidden in the depths of git.')
    parser.add_argument("--json", dest="output_json", action="store_true", help="Output in JSON")
    parser.add_argument("--html", dest="output_html", action="store_true", help="Output in HTML")
    parser.add_argument("--csv", dest="output_csv", action="store_true", help="Output in CSV")
    parser.add_argument("--regex", dest="do_regex", action="store_true", help="Enable high signal regex checks")
    parser.add_argument("--entropy", dest="do_entropy", help="Enable entropy checks")
    parser.add_argument("--since_commit", dest="since_commit", help="Only scan from a given commit hash")
    parser.add_argument("--max_depth", dest="max_depth", help="Max commit depth to go back when searching for secrets")
    parser.add_argument("--starts_with", dest="starts_with", help="Perform checks starting from N repository")
    parser.add_argument("--report", dest="report", action="store_true",
                        help="Calculate statistic if you've ready file with checks")
    parser.add_argument("--not_clone", dest="not_clone", action="store_true",
                        help="No clone or fetch repositories (in case they were cloned before")
    parser.set_defaults(regex=False)
    parser.set_defaults(max_depth=10)
    parser.set_defaults(since_commit=None)
    parser.set_defaults(entropy=False)
    parser.set_defaults(output_csv=False)
    parser.set_defaults(output_html=False)
    parser.set_defaults(output_json=False)
    parser.set_defaults(starts_with=0)
    parser.set_defaults(stats_only=False)
    parser.set_defaults(not_clone=False)
    parser.set_defaults(report=False)
    args = parser.parse_args()
    # Create dirs
    createDirs()
    # Count statistic only
    if args.report:
        _, json_file = combine_all_checks(args.output_csv, args.output_html)
        # json_file = read_json_file('results/2018-01-04-14-09-found-leaks.json')
        count_reason_stats(json_file)
        count_project_stats(json_file)
        count_repo_stats(json_file)
    # Make connection to Bitbucket
    username = CONFIG.get('BITBUCKET', 'username')
    secret = CONFIG.get('BITBUCKET', 'secret')
    owner = CONFIG.get('BITBUCKET', 'owner')
    bb_session = Bitbucket(username, secret)
    json_repos = formBitbucketReposLists(bb_session, owner)
    # json_repos = read_json_file('tmp/2018-02-04-10-52-formatted_repositories.json')
    # json_repos = prepareReposToJson(response)
    # Check particular repository
    git_urls = sorted(json_repos.keys())
    total_rep = len(json_repos.keys())
    logger.info('Fetched %s Bitbucket repositories from Company account.\n' % total_rep)
    count = int(args.starts_with)

    # Prepare pool of processes (max by default)
    processes = mp.cpu_count()
    logger.info('Amount of vCPUs - {0}\n'.format(processes))
    pool = mp.Pool()
    results = [pool.apply_async(search_bitbucket, args=(rep_count, git_urls, username, secret, args, json_repos, total_rep))
               for rep_count in range(count, total_rep)]
    for proc in results:
        proc.get()

    # Final steps
    csv_file, _ = combine_all_checks(args.output_csv, args.output_html)
    if csv_file:
        logger.info('Checks has been completed successfully. See file {0}'.format(csv_file))


if __name__ == '__main__':
    main()
