# Post Exploitation Shell Script

## Supported Distributions
 - Kali 1.1.0, CentOS 6.5, Ubuntu 14.04.2

## Running the scripts
 - $ mkdir /tmp/.root/.home/.user/
 - $ cp daily_backup.sh /tmp/.root/.home/.user/
 - $ chmod u+x daily_backup.sh
 - $ ./daily_backup.sh

 - Test snort.php
 - -> $ curl -d "eFh4R2VuPE93bmVkIEJ5IEcwZHoxbGw0PkdlbnhYeA==" -A "H4x0r Lit3 - Ph0n3H0m3 v1.0"  http://localhost/snort.php

## TODO
### Bugs:
   - Backup shell errors, needs to be worked on
   - Generated Scripts may need some work, polishing, fixing
   - Copying .history/.bash_history every run is a little excessive.

### Feature Requests:
   - Create variations of th script to match the level of threat actor
   - e.g. - level 0/1 - Script Kiddie, no tracks covering
   -        level X - Quiet, no history deletion, logs modified, etc. 
   - Use ICMPShell
   - Encrypt nc/shell traffic

### Cleanup:
   - Fix formatting
   - Add comments/Remove comments
   - Speed up processing time.

## Acknowledgements/Contributors
  - Special thanks to Justin Wray (Synister Syntax)
