#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import math
import datetime
import argparse
import os
import json
import stat
import time
import re
from regexChecks import regexes_txt, regexes_fs
from git import Repo

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "1234567890abcdefABCDEF"

# Get current date
CURR_TIME = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def str2bool(v):
    if not v:
        return True
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def del_rw(action, name, exc):
    os.chmod(name, stat.S_IWRITE)
    os.remove(name)


def shannon_entropy(data, iterator):
    """
    Borrowed from http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    """
    if not data:
        return 0
    entropy = 0
    for x in iterator:
        p_x = float(data.count(x))/len(data)
        if p_x > 0:
            entropy += - p_x*math.log(p_x, 2)
    return entropy


def get_strings_of_set(word, char_set, threshold=20):
    count = 0
    letters = ""
    strings = []
    for char in word:
        if char in char_set:
            letters += char
            count += 1
        else:
            if count > threshold:
                strings.append(letters)
            letters = ""
            count = 0
    if count > threshold:
        strings.append(letters)
    return strings


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_results(printJson, issue):
    commit_time = issue['date']
    branch_name = issue['branch']
    prev_commit = issue['commit']
    printableDiff = issue['printDiff']
    commitHash = issue['commitHash']
    reason = issue['reason']
    path = issue['path']

    if printJson:
        print(json.dumps(issue, sort_keys=True, indent=4))
    else:
        print("~~~~~~~~~~~~~~~~~~~~~")
        reason = "{}Reason: {}{}".format(bcolors.OKGREEN, reason, bcolors.ENDC)
        print(reason)
        dateStr = "{}Date: {}{}".format(bcolors.OKGREEN, commit_time, bcolors.ENDC)
        print(dateStr)
        hashStr = "{}Hash: {}{}".format(bcolors.OKGREEN, commitHash, bcolors.ENDC)
        print(hashStr)
        filePath = "{}Filepath: {}{}".format(bcolors.OKGREEN, path, bcolors.ENDC)
        print(filePath)

        if sys.version_info >= (3, 0):
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name, bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit, bcolors.ENDC)
            print(commitStr)
            print(printableDiff)
        else:
            branchStr = "{}Branch: {}{}".format(bcolors.OKGREEN, branch_name.encode('utf-8'), bcolors.ENDC)
            print(branchStr)
            commitStr = "{}Commit: {}{}".format(bcolors.OKGREEN, prev_commit.encode('utf-8'), bcolors.ENDC)
            print(commitStr)
            print(printableDiff.encode('utf-8'))
        print("~~~~~~~~~~~~~~~~~~~~~")


def find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, git_url, json_repos):
    stringsFound = []
    lines = printableDiff.split("\n")
    for line in lines:
        for word in line.split():
            base64_strings = get_strings_of_set(word, BASE64_CHARS)
            hex_strings = get_strings_of_set(word, HEX_CHARS)
            for string in base64_strings:
                b64Entropy = shannon_entropy(string, BASE64_CHARS)
                if b64Entropy > 4.5:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
            for string in hex_strings:
                hexEntropy = shannon_entropy(string, HEX_CHARS)
                if hexEntropy > 3:
                    stringsFound.append(string)
                    printableDiff = printableDiff.replace(string, bcolors.WARNING + string + bcolors.ENDC)
    entropicDiff = None
    if len(stringsFound) > 0:
        entropicDiff = {}
        entropicDiff['gitUrl'] = git_url
        entropicDiff['gitSlug'] = json_repos[git_url]['slug']
        entropicDiff['project'] = json_repos[git_url]['project']
        entropicDiff['projectName'] = json_repos[git_url]['project_name']
        entropicDiff['language'] = json_repos[git_url]['language']
        entropicDiff['date'] = commit_time
        entropicDiff['creation_date'] = CURR_TIME
        entropicDiff['path'] = blob.b_path if blob.b_path else blob.a_path
        entropicDiff['author'] = prev_commit.committer if prev_commit.committer else prev_commit.author.email
        entropicDiff['branch'] = branch_name
        entropicDiff['type'] = 'Entropy'
        entropicDiff['commit'] = prev_commit.message
        entropicDiff['diff'] = blob.diff.decode('utf-8', errors='replace')
        entropicDiff['stringsFound'] = stringsFound
        entropicDiff['printDiff'] = printableDiff
        entropicDiff['commitHash'] = commitHash
        entropicDiff['reason'] = "High Entropy"
    return entropicDiff


def idx_bound_verification(bound, idx, printableDiff):
    """
    Check if expanded boundaries in git diff are True
    :param bound:
    :param idx:
    :param printableDiff:
    :return:
    """
    lower_idx, upper_idx = (index - bound for index in idx)
    lower_boundary, upper_boundary = False, False
    while not lower_boundary:
        try:
            printableDiff[lower_idx]
            lower_boundary = True
        except ValueError:
            lower_idx += 1
    while not upper_boundary:
        try:
            printableDiff[upper_idx]
            upper_boundary = True
        except ValueError:
            upper_idx -= 1
    return lower_idx, upper_idx


def regex_txt_check(printableDiff, commit_time, branch_name, prev_commit, blob, commitHash, git_url, json_repos):
    regex_matches = []
    # Set bound for expanded code match in git diff
    bound = 30
    for key in regexes_txt.keys():
        found_strings_search = regexes_txt[key].search(printableDiff)

        # for found_string in found_strings:
        #     found_diff += bcolors.WARNING + str(found_string) + bcolors.ENDC + '\n'
        # for found_string_exp in found_strings_expand:
        #     found_diff_exp += bcolors.OKGREEN + str(found_string_exp) + bcolors.ENDC + '\n'
        # if regexes_txt[key].group:
        if found_strings_search:
            # found_strings, found_strings_exp, found_strings_clr = '', '', ''
            idx = found_strings_search.regs[0]
            found_string = re.sub(r'(\r|\n)', '', str(printableDiff[idx[0]:idx[1]]))
            # found_strings += found_string
            # found_strings_clr += bcolors.WARNING + found_string + bcolors.ENDC
            lower_idx, upper_idx = idx_bound_verification(bound, idx, printableDiff)
            found_string_exp = re.sub(r'(\r|\n)', '', str(printableDiff[lower_idx:upper_idx]))
            # found_strings_exp += found_string_exp

            found_regex = {}
            found_regex['gitUrl'] = git_url
            found_regex['gitSlug'] = json_repos[git_url]['slug']
            found_regex['project'] = json_repos[git_url]['project']
            found_regex['projectName'] = json_repos[git_url]['project_name']
            found_regex['language'] = json_repos[git_url]['language']
            found_regex['commit_date'] = commit_time
            found_regex['audit_date'] = CURR_TIME
            try:
                found_regex['path'] = blob.a_blob.abspath if blob.a_blob.abspath else blob.a_path
            except AttributeError:
                found_regex['path'] = blob.b_blob.abspath if blob.b_blob.abspath else blob.abspath
            found_regex['branch'] = branch_name
            found_regex['commit'] = re.sub(r'(\r|\n)', '', prev_commit.message)
            found_regex['author'] = prev_commit.committer.name if prev_commit.committer.name else prev_commit.author.email
            diff = re.compile('(^.+?)\n').findall(printableDiff)
            found_regex['diff'] = "Diff details: " + str(diff) + '\nMatched string in diff context:\n' + \
                                  "-----begin omitted-----\n" + found_string_exp + "\n-----end omitted-----",
            found_regex['type'] = 'MatchStringInDiff'
            found_regex['stringsFound'] = found_string
            # found_regex['printDiff'] = ''
            found_regex['reason'] = key
            found_regex['commitHash'] = commitHash
            regex_matches.append(found_regex)
    return regex_matches


def regex_fs_check_tree(commit_time, branch_name, prev_commit, commitHash, git_url, json_repos):
    regex_matches = []
    for file_git in prev_commit.tree.blobs:
        for key in regexes_fs:
            repo_path = file_git.abspath.split("/repos/")[-1]
            found_strings = regexes_fs[key].search(repo_path)
            if found_strings:
                # found_strings, found_strings_exp, found_strings_clr = '', '', ''
                for idx in found_strings.regs:
                    found_string = re.sub(r'(\r|\n)', '', str(repo_path[idx[0]:idx[1]]))

                    found_regex = {}
                    found_regex['gitUrl'] = git_url
                    found_regex['gitSlug'] = json_repos[git_url]['slug']
                    found_regex['project'] = json_repos[git_url]['project']
                    found_regex['projectName'] = json_repos[git_url]['project_name']
                    found_regex['language'] = json_repos[git_url]['language']
                    found_regex['commit_date'] = commit_time
                    found_regex['audit_date'] = CURR_TIME
                    found_regex['path'] = repo_path
                    found_regex['branch'] = branch_name
                    found_regex['author'] = prev_commit.committer.name if prev_commit.committer.name else prev_commit.author.email
                    found_regex['commit'] = re.sub(r'(\r|\n)', '', prev_commit.message)
                    found_regex['diff'] = ''
                    found_regex['type'] = 'MatchInFilename'
                    found_regex['stringsFound'] = found_string
                    found_regex['reason'] = key
                    found_regex['commitHash'] = commitHash
                    regex_matches.append(found_regex)
    return regex_matches


# def searchSensitiveFilesInRepo(project_path, git_url, json_repos):
#     """
#     Deprecated function
#     :param project_path:
#     :param git_url:
#     :param json_repos:
#     :return:
#     """
#     fs_objects = os.listdir(project_path)
#     # repo = Repo(project_path)
#     # changed = [item.a_path for item in repo.index.diff(None) ]
#     foundIssues = []
#     for fs_object in fs_objects:
#         found_regexes = regex_fs_check_tree(fs_object, git_url, json_repos)
#         foundIssues += found_regexes
#     return foundIssues


def find_strings(project_path, git_url, json_repos, since_commit=None, max_depth=None, do_regex=False, do_entropy=True):
    """
    Serch sensitive data in git commit diffs
    :param project_path: string
    :param git_url: string
    :param json_repos: dictionary
    :param since_commit: integer
    :param max_depth: integer
    :param do_regex: boolean
    :param do_entropy: boolean
    :return: dictionary
    """
    repo = Repo(project_path)
    already_searched = set()

    found_issues = []
    for remote_branch in repo.remotes.origin.fetch():
        since_commit_reached = False
        branch_name = remote_branch.name.split('/')[1]
        try:
            repo.git.checkout(remote_branch, b=branch_name)
        except:
            pass
        prev_commit = None
        for curr_commit in repo.iter_commits(max_count=max_depth):
            commitHash = curr_commit.hexsha
            if commitHash == since_commit:
                since_commit_reached = True
            if since_commit and since_commit_reached:
                prev_commit = curr_commit
                continue
            if not prev_commit:
                pass
            else:
                # Avoid searching the same diffs
                hashes = str(prev_commit) + str(curr_commit)
                if hashes in already_searched:
                    prev_commit = curr_commit
                    continue
                already_searched.add(hashes)

                diff = prev_commit.diff(curr_commit, create_patch=True)
                for blob in diff:
                    printableDiff = blob.diff.decode('utf-8', errors='replace')
                    if printableDiff.startswith("Binary files"):
                        continue
                    commit_time = datetime.datetime.fromtimestamp(prev_commit.committed_date).strftime('%Y-%m-%d %H:%M:%S')
                    foundIssues = []
                    if do_entropy:
                        entropicDiff = find_entropy(printableDiff, commit_time, branch_name, prev_commit, blob,
                                                    commitHash, git_url, json_repos)
                        if entropicDiff:
                            foundIssues.append(entropicDiff)
                    if do_regex:
                        found_regexes = regex_txt_check(printableDiff, commit_time, branch_name, prev_commit, blob,
                                                        commitHash, git_url, json_repos)
                        foundIssues += found_regexes
                        found_files = regex_fs_check_tree(commit_time, branch_name, prev_commit, commitHash, git_url,
                                                          json_repos)
                        foundIssues += found_files

                    for foundIssue in foundIssues:
                        # print_results(printJson, foundIssue)
                        # print("Issue is ", foundIssue)
                        found_issues.append(foundIssue)

            prev_commit = curr_commit
    # output["project_path"] = project_path
    # shutil.rmtree(project_path, onerror=del_rw)
    return found_issues

