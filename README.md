# Bitbucket Trufflehog

Multithreading search through Bitbucket git repositories for sensitive data (see TruffleHog/regexChecks.py), digging deep into commit history, branches and filenames. 
This is effective at finding secrets accidentally committed.
Regex patterns were expanded with rules from PasteHunter, Gitrob and mien own

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. 
See deployment for notes on how to deploy the project on a live system.

### Prerequisites and Installing ###
Install all Py modules described in requirements.txt. 

```
clone repository
cd repository
pip install virtualenv
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Configuration ###
Rename config template  .config/config.template to bitbucket-creds-checker/.config/config.cfg and add you credentials
```bash
[BITBUCKET]
username = ADD_YOUR_OWN_USERNAME
secret = ADD_YOUR_OWN. Create separate App password in Bitbucket account with custom permissions
owner = ADD_YOUR_OWN

```

### Running ###
How to use tool please read original Readme from TruffleHog: https://github.com/dxa4481/truffleHog


### Customizing ###
Custom regexes can be added to the following file:
```
truffleHog/truffleHog/regexChecks.py
```


### Running Examples ###
Check Bibucket account with regex but without entropy, starting from 1st repo slug 
(sorted by ASC) and saving output to: html, csv
```
python bitchecker.py --regex --csv --html --entropy=False --starts_with 0
```
Check Bibucket account with regex but with entropy, maximum 5 last commits and saving output to: csv
```
python bitchecker.py --regex --csv --entropy=True --max_depth 5  
```
Check Bibucket account with regex but with entropy, not cloning or fetching repository and 
saving output to: csv
```
python bitchecker.py --regex --csv --entropy=True --not_clone
```
Prepare report and statistic only for previous Bitbucker account analyze. See report in folder results/
```
python bitchecker.py --regex --csv --entropy=True --report
```

### Help ###

```
usage: bitchecker.py [-h] [--json] [--html] [--csv] [--regex]
                     [--entropy DO_ENTROPY] [--since_commit SINCE_COMMIT]
                     [--max_depth MAX_DEPTH] [--starts_with STARTS_WITH]
                     [--report] [--not_clone]

Find secrets hidden in the depths of git.

optional arguments:
  -h, --help            show this help message and exit
  --json                Output in JSON
  --html                Output in HTML
  --csv                 Output in CSV
  --regex               Enable high signal regex checks
  --entropy DO_ENTROPY  Enable entropy checks
  --since_commit SINCE_COMMIT
                        Only scan from a given commit hash
  --max_depth MAX_DEPTH
                        Max commit depth to go back when searching for secrets
  --starts_with STARTS_WITH
                        Perform checks starting from N repository
  --report              Calculate statistic if you've ready file with checks
  --not_clone           No clone or fetch repositories (in case they were
                        cloned before
### ToDo
--- Add multithreading support. Very actual for large git repositories
--- Improve regex pattern for sensitive data search