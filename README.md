PowerShell Script for Windows Server Compliance / Security Configuration Audit

This script checks for various security settings / controls / policies applied on the host machine. The script also tells what the recommended value of a setting / control / policy should be according to known security standards. This script comes in handy in situations where running automated configuration audit tools like Nipper or Nessus (with configuration audit policy configured) is not allowed.

To see a sample output of what the script will generate, see the sample_output.txt file.

Usage:

1. Open PowerShell with Administrator privileges.
2. Before executing the script ensure that the PowerShell Script Execution Policy is set to Unrestricted.
3. This can be done by running the command "Set-ExecutionPolicy Unrestricted -Force" in PowerShell.
4. Navigate to the script directory and run the script.
5. Once the script execution is complete, the output can be found in the script directory itself.

Reference from: https://github.com/Sikkandar-Sha/SEC-AUDIT/
