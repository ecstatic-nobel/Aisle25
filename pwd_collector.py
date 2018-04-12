#!/usr/bin/python
"""
Use the usernames of failed logins seen in the Windows Security logs to determine 
the password of authorized users. The log file must be in CSV format with the 
following case-sensitive headers in order:

EventID              : Only event IDs 4624 and 4625 are needed
Domain               : The domain of the computer attempting to be accessed
User                 : The user accounts authorized to access the host
ComputerName         : The localhost generating the logs
SourceNetworkAddress : The source computer's IP address
"""

import collections
import sys
import passwordmeter
import config


class PWDC:
    def init(self):
        """ """

    def convert_csv_dict(self, filename):
        """Convert a CSV formatted file to a dictionary."""

        open_file = open(filename, 'r')
        contents  = open_file.read().splitlines()
        open_file.close()

        header     = contents[0]
        body       = contents[1:]
        keys       = header.replace('"', '').split(',')
        values     = []
        tvalues    = [line.replace('"', '').split(',') for line in body]
        for tvalue in tvalues: # rejoin passwords containing commas
            tlist = []
            tlist.append(tvalue[0])
            tlist.append(tvalue[1])
            tlist.append(tvalue[-2])
            tlist.append(tvalue[-1])
            tvalue.pop(0)
            tvalue.pop(0)
            tvalue.pop(-1)
            tvalue.pop(-1)
            tlist.insert(2, ','.join(tvalue))
            values.append(tlist)
        dictionary = [collections.OrderedDict(zip(keys, value)) for value in values]

        return dictionary

    def gather_logins(self, csv_data):
        """Generate list of login attempts starting with failed logins."""

        logins = []

        for row in csv_data:
            if row['EventID'] == '4624' or row['EventID'] == '4625':
                logins.append(row)

        return logins

    def get_pwd(self, login_data):
        """Generate hash table of strings with high entropy followed by successful logons."""

        pwds = []

        for login in login_data:
            if login['EventID'] == '4625':
                username = login['User']
                pwdtest  = passwordmeter.test(username)
                strength = pwdtest[0]

                if strength > .5:
                    login['Possible Password']    = username
                    login['User']                 = 'Possible usernames are seen before the next failed login'
                    login['Password Possibility'] = str(strength)
                    pwds.append(login)
                    index                         = pwds.index(pwds[-1])

                continue

            if len(pwds) == 0: continue

            if login['EventID'] == '4624':
                domain            = login['Domain']
                username          = login['User']
                previous_computer = pwds[index]['ComputerName']
                current_computer  = login['ComputerName']
                previous_source   = pwds[index]['SourceNetworkAddress']
                current_source    = login['SourceNetworkAddress']
                possible_password = pwds[index]['Possible Password']

                if previous_computer == current_computer and previous_source == current_source:
                    login['Possible Password']    = '---'
                    login['Password Possibility'] = '---'
                    
                    if pwds[-1] != login:
                        pwds.append(login)
                        msg1 = 'Possible Credentials Detected: '
                        msg2 = 'Try logging onto %s as %s\%s with the password %s' % (previous_computer,
                                                                                      domain,
                                                                                      username,
                                                                                      possible_password)
                        print msg1+msg2

        return pwds

    def convert_dict_csv(self, dictionary):
        """Convert a dictionary to CSV-formatted data."""

        csv    = []
        keys   = dictionary[0].keys()
        header = '","'.join(keys)

        csv.append('"%s"' % header)

        for item in dictionary:
            row = '","'.join(item.values())
            csv.append('"%s"' % row)

        return csv

    def write_output(self, csv_data):
        """Write output to a file"""
        with open(config.output_file, 'w') as outputFile:
            for line in csv_data:
                outputFile.write('%s\n' % line)

        return

def main():
    """ """
    pwdc       = PWDC()
    dict_data  = pwdc.convert_csv_dict(config.wineventlogs)
    login_data = pwdc.gather_logins(dict_data)
    pwd_data   = pwdc.get_pwd(login_data)
    csv_data   = pwdc.convert_dict_csv(pwd_data)

    pwdc.write_output(csv_data)

    return

if __name__ == '__main__':
    main()
