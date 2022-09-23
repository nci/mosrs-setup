# mosrs-setup

Scripts to set up access to the MOSRS repository for NCI users.

`mosrs-setup`: Sets up GPG agent for storing MOSRS passwords (`mosrs/setup.py`)

`mosrs-auth`: Saves a user's MOSRS password (`mosrs/auth.py`)

`nciws-auth`: Saves a user's NCI password for web server access (`mosrs/nciws.py`)

Passwords are stored in `gpg-agent`, using the interface in `mosrs/gpg.py`. 

Note that `mosrs-setup` is intended to only run `gpg-agent` in interactive login shells and not in batch jobs.

