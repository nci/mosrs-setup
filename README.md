# mosrs-setup

Scripts to set up access to the MOSRS repository for NCI users.

`mosrs-setup`: Sets up GPG agent for storing MOSRS passwords (`mosrs/setup.py`)

`mosrs-auth`: Saves a user's MOSRS password (`mosrs/auth.py`)

Passwords are stored in `gpg-agent`, using the interface in `mosrs/gpg.py`. 

Note that `mosrs-setup` is intended to only run `gpg-agent` in interactive login shells and not in batch jobs.

## Usage and expected outputs

`mosrs-setup`:
```
usage: mosrs-setup [-h] [--debug]

Set up MOSRS authentication for Rose and Subversion by storing credentials

optional arguments:
  -h, --help  show this help message and exit
  --debug     enable printing of debug messages
```
- Use this command once per `$HOME` directory as an initial setup.
- It performs the actions listed under `mosrs-auth` below.
- It also edits your `$HOME/.bashrc` file, if necessary. The updated `.bashrc` file starts up `gpg-agent` automatically for interactive login shells.
  - If `$HOME/.bashrc` is changed, it is first backed up to the directory `$HOME/.mosrs-setup/backup.$TODAY.$PID` where `$TODAY` is today's date in ISO format and `$PID` is the current process ID.
    - The backup is best-effort. If the backup fails, a warning is given and the changes are still made.
  - If you do not want your `$HOME/.bashrc` file changed, do not run `mosrs-setup`. Just run `mosrs-auth` instead.

`mosrs-auth`:
```
usage: mosrs-auth [-h] [--debug] [--force]

Cache password to MOSRS for Rose and Subversion

optional arguments:
  -h, --help  show this help message and exit
  --debug     enable printing of debug messages
  --force     force cache refresh of both username and password
```
- Use this command once in every interactive login session where you want to use the upstream MOSRS repository. Run `mosrs-auth` before running any `fcm`, `svn`, `rose` or `rosie` command that uses MOSRS.
- It performs the following actions:
  - Uses `wget` to check connectivity to MOSRS.
  - Uses `which rose` to check that the `rose` command is available.
  - Checks the file `$HOME/.gnupg/gpg-agent.conf` and updates it if necessary.
  - Starts `gpg-agent` and runs it for a maximum of 12 hours as per the settings in the file `$HOME/.gnupg/gpg-agent.conf`.
  - Defines the environment variables `GPG_AGENT_INFO` and `GPG_TTY`.
  - Runs `rose config` to obtain your MOSRS username from the Rose configuration. It is assumed to be in `$HOME/.metomi/rose.conf`.
  - Parses the file `$HOME/.subversion/servers` to obtain your MOSRS username.
  - Checks that the MOSRS usernames obtained from `rose config` and `$HOME/.subversion/servers` match.
  - Runs `svn info` interactively to store your MOSRS username and related information in a file in the directory `$HOME/.subversion/auth/svn.simple`, if this information is not already stored there.
  - Creates the file `$HOME/.subversion/servers` and adds your MOSRS username there, if your username is not already stored there.
  - Creates the directory `$HOME/.metomi` and the file `$HOME/.metomi/rose.conf` and adds your MOSRS username there, if your username is not already stored there.
  - Caches your MOSRS password for at most 12 hours, and checks it using both `svn` and `rosie`.
  - If any files in any of the `$HOME/.gnupg`, `$HOME/.metomi` or `$HOME/.ssh` directories are changed, the whole directory is first backed up to the directory `$HOME/.mosrs-setup/backup.$TODAY.$PID` where `$TODAY` is today's date in ISO format and `$PID` is the current process ID.
    - The backup is best-effort. If the backup fails, a warning is given and the changes are still made.
