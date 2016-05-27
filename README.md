# ljdumpgo
LiveJournal backup utility in Go

This is a port of the [ljdump.py](https://github.com/ghewgill/ljdump) utility to Go to backup LiveJournal user and community posts and comments. 

The software should be considered alpha-version qulity and used with extreme causion.

##Compatibilty with ljdump.py
ljdumpgo reads most configuration and database files created by ljdump.py and can be used to continue archiving the data previously downloaded by that utility. The only exception is `userpics.xml` file and corresponding image files. As ljdump.py downloads those files each time it runs, ljdumpgo replaces that with separated `account.data` directory that stores the picture files and meta-information about them allowing to skip downloads if the files have not chnaged.

ljdumpgo does not support writing meta-information about the state of comments using Python-specific pickle files. Instead diff-firendly plain text files that can easly be edited by hands are used. Thus running the Python utility after ljdumpgo downloaded some posts or comments will re-download those again.

