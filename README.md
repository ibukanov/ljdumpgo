# ljdump-go
LiveJournal backup utility in Go

This is a port of the [ljdump.py](https://github.com/ghewgill/ljdump) utility to Go to backup LiveJournal user and community posts and comments. It reads all configuration and database files created by ljdump.py and can be used to continue archiving the data previously downloaded by that utility. However, as ljdump-go stores meta-information about the state of posts and comments using files in the standard  [json](http://www.json.org/) format rather than Python-specific pickle files, the backup process cannot be switched back to use the Python utility.

The software should be considered alpha-version qulity and used with extreme causion.
