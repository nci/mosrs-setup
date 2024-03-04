# mosrs-setup

Scripts to set up access to the MOSRS repository for NCI users.

## Usage and expected outputs

`mosrs-auth`:
```
usage: mosrs-auth [-h] [--force]

Cache password to MOSRS for Rose and Subversion

optional arguments:
  -h, --help  show this help message and exit
  --force     force cache refresh of both username and password
```
- Use this command once in every interactive login session where you want to use the upstream MOSRS repository. Run `mosrs-auth` before running any `fcm`, `svn` or `rosie` command that uses MOSRS.
