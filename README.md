# mosrs-setup

Scripts to set up access to the MOSRS repository for NCI users.

`mosrs-setup`: Sets up GPG agent for storing MOSRS passwords (`mosrs/setup.py`)

`mosrs-auth`: Saves a user's MOSRS password (`mosrs/auth.py`)

`nciws-auth`: Saves a user's NCI password for web server access (`mosrs/nciws.py`)

Passwords are stored in `gpg-agent`, using the interface in `mosrs/gpg.py`. 

Note that `mosrs-setup` is intended to only run `gpg-agent` in interactive login shells and not in batch jobs.

## Usage and expected outputs

`mosrs-setup`:
- Is intended for use once per `$HOME` directory as an initial setup.
- Starts `gpg-agent` and runs it for a maximum of 12 hours.
- Defines the environment variables `GPG_AGENT_INFO` and `GPG_TTY`.
- Creates `$HOME/.subversion/servers` and add your MOSRS username there, if your username is not already defined.
- Caches your MOSRS password for at most 12 hours, and checks it using both `svn` and `rosie`.
- Edits your `$HOME/.bashrc` file, after moving or copying it to `$HOME/.bashrc.old`. The updated `.bashrc` file starts up `gpg-agent` automatically for interactive login shells.
- If you do not want your `$HOME/.bashrc` file changed, do not run `mosrs-setup`. Just run `mosrs-auth` instead.

`mosrs-auth`:
- Is intended for every interactive login session when you want to run `fcm`, `svn`, `rose` or `rosie` to use the upstream MOSRS repository. Run `mosrs-auth` before any of these other commands.
- Starts `gpg-agent` and runs it for a maximum of 12 hours.
- Defines the environment variables `GPG_AGENT_INFO` and `GPG_TTY`.
- Creates `$HOME/.subversion/servers` and add your MOSRS username there, if your username is not already defined.
- Caches your MOSRS password for at most 12 hours, and checks it using both `svn` and `rosie`.

