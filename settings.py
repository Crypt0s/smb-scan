#Turning this on will attempt to connect to the server anonymously without using the domain credentials
ANONYMOUS = True

# Domain credentials for scanning
USERNAME = ''
PASSWORD = ''
DOMAIN = ""

TARGET_LIST = "targets.txt"

# This will output an "ls"-style output for easy grepping/awking
OUTPUT_FILE = "out.txt"

# Limit the number of connections -- we make one SMB scanner thread per system in the targets file
MAX_THREADS = 10
