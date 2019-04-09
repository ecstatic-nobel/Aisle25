# [Aisle25™]  
##### Use the username of failed logons seen in the Windows Security logs to alert on clear-text passwords of authorized users.  

### Description  
Ever been distracted and ended up typing your password in the username/email field? Ever wonder where there logs go? Well, I'm pretty sure all failed (and successful) logons get logged somewhere. Using these logs, an insider doesn't need to worry about cracking hashes. They just need to wait for the right time (early Monday morning or when you're rushing back from lunch) to get your password for free because you'll blindly provide it to them. And not just at work either. This could happen when logging into any account (banks, shopping, school, etc.).  

What is the solution?  

- If you are running a Windows 10 shop, use Protected Event Logging.  
- Or, Deny administrators the privilege to create usernames with high entropy and passwords with low entropy.  
- Or, Harden the logon process. Don't allow it to accept/log failed logons attempts of usernames with high entropy.  

Problem solved?  

Not quite. What happens if you are using a log aggregator like Splunk and those protected logs now have to become visible to detect threats? The best solution is to alert the System Administrator as soon as possible. No matter if it's internal, no one should know it except for the user.  

To determine possible passwords and usernames:  
- Start with the first failed logon (EventCode 4625)  
- Calculate the entropy of the string in the User field  
- If the entropy is high, add it to a list and mark it as a possible password  
- Add all of the successful logons that follow from the same source as potential usernames to use  
- Continue this loop until the entire log file is read  

Muahahahahaha!!!!!!

Now you can use this evil theory for good and alert when these events take place in your environment.  

### Prerequisites  
- Git  
- Python 2.7.14  
- Python Pip  
- PasswordMeter  

### Install via Splunk Web  
In Splunk Web:  
- Navigate to `Find More Apps`  
- Search for `Aisle25`  
- Identify the app and click `Install`  
- Login with your Splunk.com credentials  
- Click `Restart Now`  
- Click `Open App`  
- Open a terminal and run the following commands:  
```bash
cd <SPLUNK_HOME>/etc/apps/Aisle25/bin
bash py_pkg_update.sh
```

### Manual Setup  
Open a terminal and run the following commands:  
```bash
cd <SPLUNK_HOME>/etc/apps
git clone https://github.com/ecstatic-nobel/Aisle25.git
cd Aisle25/bin
bash py_pkg_update.sh
```

Restart Splunk.  

### Usage  
In Splunk:  
- Switch to the PwdLeak dashboard in the Aisle25™ app.  
- Enter the base search in the `Base Search` text box (default: `sourcetype=wineventlog EventCode IN (4624, 4625)`).  
- Choose the time constraint for the logs you want to analyze.  
- Click `Submit`.  

The output of the base search should be a table with a minimum of the following case-sensitive fields:  
- _time  
- EventCode  
- Account_Domain  
- Account_Name  
- ComputerName  
- Source_Network_Address  

![pwdleak](https://raw.githubusercontent.com/ecstatic-nobel/Aisle25/master/static/assets/pwdleak.png)  

The panel to the bottom left will show the raw logs formatted as a table with the required fields. The panel to the bottom right are the results containing possible usernames and passwords. The most efficient way to use this is to setup alerts for when these events take place on your network and notify the System Administrators so they can take action to reset the password.  

### Destroy
To remove the project completely, run the following commands:  
```bash
cd $SPLUNK_HOME/etc/apps
rm -rf Aisle25
```
Finally, restart Splunk.  

### Things to Know  
- Be responsible!!!   
- Password with a comma will not be detected  
