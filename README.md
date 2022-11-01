# mosrs-setup

Scripts to set up access to the MOSRS repository for NCI users.

`mosrs-setup`: Sets up GPG agent for storing MOSRS passwords (`mosrs/setup.py`)

`mosrs-auth`: Saves a user's MOSRS password (`mosrs/auth.py`)

Passwords are stored in `gpg-agent`, using the interface in `mosrs/gpg.py`. 

Note that `mosrs-setup` is intended to only run `gpg-agent` in interactive login shells and not in batch jobs.

## Usage and expected outputs

`mosrs-setup`:
- Is intended for use once per `$HOME` directory as an initial setup.
- Performs the actions listed under `mosrs-auth` below.
- Also edits your `$HOME/.bashrc` file, after moving or copying it to `$HOME/.bashrc.old`. The updated `.bashrc` file starts up `gpg-agent` automatically for interactive login shells.
  - If you do not want your `$HOME/.bashrc` file changed, do not run `mosrs-setup`. Just run `mosrs-auth` instead.

`mosrs-auth`:
- Is intended for every interactive login session when you want to run `fcm`, `svn`, `rose` or `rosie` to use the upstream MOSRS repository. Run `mosrs-auth` before any of these other commands.
- Performs the following actions:
  - Starts `gpg-agent` and runs it for a maximum of 12 hours.
  - Defines the environment variables `GPG_AGENT_INFO` and `GPG_TTY`.
  - Runs `svn info` interactively to store your MOSRS username and related information in a file in the directory `SHOME/.subversion/auth/svn.simple`, if this information is not already stored there.
  - Creates the file `$HOME/.subversion/servers` and adds your MOSRS username there, if your username is not already defined.
  - Caches your MOSRS password for at most 12 hours, and checks it using both `svn` and `rosie`.

