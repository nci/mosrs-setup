# mosrs-setup

Scripts to set up access to MOSRS repository

mosrs-setup: Sets up a users's MOSRS account as well as GPG agent for storing passwords (mosrs/setup.py)

mosrs-auth: Saves a user's MOSRS password (mosrs/auth.py)

access-auth: Saves a user's access-svn password (mosrs/access.py)

Passwords are stored in gpg-agent, using the interface in mosrs/gpg.py. Regardless of if MOSRS is being used, mosrs-setup should be run to set up gpg-agent (this only needs to be done once)
