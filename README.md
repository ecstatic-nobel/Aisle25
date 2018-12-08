# [password_collector]  
##### Use the username of failed logons seen in the Windows Security logs to determine the password of authorized users.  

#### Description  
Ever been distracted and ended up typing your password in the username/email field? Ever wonder where there logs go? Well, I'm pretty sure all failed (and successful) logons get logged somewhere. Using these logs, an insider doesn't need to worry about cracking hashes. They just need to wait for the right time (early Monday morning or when you're rushing back from lunch) to get your password for free because you'll blindly provide it to them. And not just at work either. This could happen when logging onto any account (banks, shopping, school, etc.).  

What is the solution? Deny administrators the privilege to create usernames with high entropy and passwords with low entropy. Finally, harden the logon process. Don't allow it to accept/log failed logons attempts of usernames with high entropy. Problem solved!!!  

On a Windows host, these logon attempts are found in the Security logs (Event ID 4624: Successful Logon, Event ID 4625: Failed Logon). To determine possible passwords and usernames:  
- Start with the first failed logon  
- Calculate the entropy of the string in the username field  
- If the entropy is high, add it to a list and mark it as a possible password  
- Add all the successful logons that follow seen from the same source as the failed logon  
- Continue this loop until the entire log file is read  

Now you have a possible password and followed by possible usernames. Guilty of typing your password in the wrong field? Make sure you change it next time this happens. This project is a PoC.  

#### Prerequisites  
- Python 2.7.14  
- Python PasswordMeter module  

#### Setup  
Open a terminal and run the following commands:  
```bash
git clone https://github.com/leunammejii/password_collector.git
cd password_collector
sudo pip install -r requirements -t .
```

#### Password Collector  
Collect the logs for logon attempts, run the following command a Windows host (Win 7 or above):  
```powershell
.\WinEventSecurityLogons.ps1 -OutputFile OUTPUTFILE
```

The `OUTPUTFILE` is whatever name you choose. 

Next, open `config.py` and add the full path of the exported Windows logs and the preferred path of where you would like to save the CSV-formatted password data. Running the Python script was only tested on a Linux computer but should work on Windows. If you are running this on Windows, make sure you escape the backslashes in the file path. 

To run the script, run the following command:  
```python
python password_collector.py
```

Using the sample data, the following will be printed to the screen:
```bash
Possible Credentials Detected: Try logging onto fakecomputer1 as pwdc\fakeuser1 with the password ty&BSQ@&b7meYGx*
Possible Credentials Detected: Try logging onto fakecomputer3 as pwdc\fakeuser2 with the password 3xG@LG29eZj!o8q@
Possible Credentials Detected: Try logging onto fakecomputer3 as pwdc\fakeuser3 with the password 3xG@LG29eZj!o8q@
Possible Credentials Detected: Try logging onto fakecomputer2 as pwdc\fakeuser2 with the password Q7UopH*he,yL6,R!cc
```

A sample of the output file can be found [here](https://github.com/leunammejii/password_collector/blob/master/sample_password_dump.csv). If you convert this to a custom Splunk command, you can use the output to setup alerts for when these events take place on your network. Administrators can then take action to reset the password (hoping that your administrator is not the insider) and remove the possibility of an inside threat selling it to the dark army (Get it? Dark army? Mr. Robot? Ok, forget it).  

#### Destroy
To remove the project completely,  run the following commands:  
```bash
rm -rf password_collector
```

#### Things to Know  
- The possible password does not garauntee that the user typed it in correctly but it does give one a head start to figuring it out.  
- Password with a comma will not be detected  
