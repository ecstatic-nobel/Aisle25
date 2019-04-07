#!/usr/bin/python
"""
Description: Use the usernames of failed logins seen in the Windows Security logs to determine 
the password of authorized users. The script accepts the following case-sensitive 
headers:

_time                  : Splunk default field for the time
EventCode              : Only event IDs 4624 and 4625 are needed
Account_Domain         : The domain of the computer attempting to be accessed
Account_Name           : The user account authorized to access the destination host
ComputerName           : The name of the source host
Source_Network_Address : The IP address of the source host

Source: https://github.com/ecstatic-nobel/Aisle25

Instructions:
1. Switch to the PwdLeak dashboard in the Aisle25 app.
2. Add the base search to the "Base Search" textbox. This search should output a 
table with the needed case-sensitive headers.
3. Select the time constraint.
4. Click "Submit".

Rate Limit: None

Results Limit: None

Debugger: open("/tmp/splunk_script.txt", "a").write("{}: <MSG>\n".format(<VAR>))
"""

import collections
import os
import re
import sys
import traceback

app_home   = "{}/etc/apps/Aisle25".format(os.environ['SPLUNK_HOME'])
tp_modules = "{}/bin/_tp_modules".format(app_home)
sys.path.insert(0, tp_modules)
import passwordmeter
import splunk.Intersplunk as InterSplunk


def get_logins(results):
    """Generate list of login attempts starting with failed logins."""
    logins = []

    for result in results:
        if result['EventCode'] == '4624' or result['EventCode'] == '4625':
            logins.append(result)
    return logins

def get_pwd(logins):
    """Generate hash table of strings with high entropy followed by successful logons."""
    pwds = []

    for login in logins:
        if login['EventCode'] == '4625':
            poss_pwd = login['Account_Name']
            pwdtest  = passwordmeter.test(poss_pwd)
            strength = pwdtest[0]

            if strength > .5:
                login['Possible_Username']   = []
                login['Possible_Password']    = poss_pwd
                login['Password_Possibility'] = str(strength)
                pwds.append(login)
                index                         = pwds.index(pwds[-1])
            continue

        if len(pwds) == 0:
            continue

        if login['EventCode'] == '4624':
            username          = login['Account_Name']
            previous_computer = pwds[index]['ComputerName']
            current_computer  = login['ComputerName']
            previous_source   = pwds[index]['Source_Network_Address']
            current_source    = login['Source_Network_Address']

            if previous_computer == current_computer and previous_source == current_source:
                if username not in pwds[index]['Possible_Username']:
                    pwds[index]['Possible_Username'].append(username)
    return pwds

def main():
    """ """
    try:
        results, dummy_results, settings = InterSplunk.getOrganizedResults()
        logins = get_logins(results)
        new_results = get_pwd(logins)
    except:
        stack = traceback.format_exc()
        new_results = InterSplunk.generateErrorResults("Error: " + str(stack))

    InterSplunk.outputResults(new_results)
    return

if __name__ == '__main__':
    main()
