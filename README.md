# About splunkdefeat

splunkdefeat is a [Splunk Enterprise SDK for Python](https://dev.splunk.com/enterprise/docs/devtools/python/sdk-python/) wrapper to help red teamers conduct multiple attack techniques against Splunk. The motivation for this proof-of-concept tool was to illustrate practical attacks against Splunk, the associated risks, and how defenders can implement countermeasures. The author assumes no liability for use of this tool.

A more detailed write-up can be found here: [splunkdefeat — A Splunk SDK wrapper for red teams](https://markernest.medium.com/splunkdefeat-a-splunk-sdk-wrapper-for-red-teams-a47a4eeeae7)

# Installation

Clone the repository:

```
git clone git@github.com:markernest0/splunkdefeat.git
```

## Python Dependencies

splunkdefeat depends on the `python-dotenv`, `prettytable` and `splunk-sdk` python modules.

Install the python dependencies:

```
pip install -r requirements.txt
```

# Usage

| Short Form    | Long Form     | Description | Tactic | Technique | Sub-Technique
| ------------- | ------------- | ------------- | ------------- | ------------- |------------- |
| -h | --help | show this help message and exit | - | - | - |
| -au | --add_user | Enter the username to create | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Create Account](https://attack.mitre.org/techniques/T1136/) | [Cloud Account](https://attack.mitre.org/techniques/T1136/003/) |
| -ap | --assign_password | Enter the password of the new user | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Create Account](https://attack.mitre.org/techniques/T1136/) | [Cloud Account](https://attack.mitre.org/techniques/T1136/003/) |
| -ar | --assign_role  | Specify the role of the new user (default choice is admin). Choices: {admin,power,user} | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Create Account](https://attack.mitre.org/techniques/T1136/) | [Cloud Account](https://attack.mitre.org/techniques/T1136/003/) |
| -ur | --update_role | Specify the role to update with a capability. Choices: {admin,power,user} | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Account Manipulation](https://attack.mitre.org/techniques/T1098/) | [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) |
| -uc | --update_capability | Specify the capability to add to a role. Choices: {admin_all_objects, schedule_search, edit_user,mdelete_by_keyword, all} | [Persistence](https://attack.mitre.org/tactics/TA0003/) | [Account Manipulation](https://attack.mitre.org/techniques/T1098/) | [Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/) |
| -ue | --update_email | Enter the new email address for alerts | [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [Impair Defenses](https://attack.mitre.org/techniques/T1562/) | [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| -ds | --disable_searches | Disable all searches | [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [Impair Defenses](https://attack.mitre.org/techniques/T1562/) | [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| -es | --enable_searches | Enable all searches | [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [Impair Defenses](https://attack.mitre.org/techniques/T1562/) | [Disable or Modify Tools](https://attack.mitre.org/techniques/T1562/001/) |
| -sh | --splunk_host | Domain name or IP address to enumerate | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force](https://attack.mitre.org/techniques/T1110/) | - |
| -sp | --splunk_port | Connect to the host on the tcp port. default=8089 | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force](https://attack.mitre.org/techniques/T1110/) | - |
| -su | --splunk_user | Specify the username | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force](https://attack.mitre.org/techniques/T1110/) | - |
| -sf | --password_file | Specify the use of a password file | [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [Brute Force](https://attack.mitre.org/techniques/T1110/) | - |
| -lu | --list_user | List current user | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Account Discovery](https://attack.mitre.org/techniques/T1087/) | [Cloud Account](https://attack.mitre.org/techniques/T1087/004/) |
| -la | --list_all | List all users | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Account Discovery](https://attack.mitre.org/techniques/T1087/) | [Cloud Account](https://attack.mitre.org/techniques/T1087/004/) |
| -lr | --list_roles | List all roles  | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Permission Groups Discovery](https://attack.mitre.org/techniques/T1069/) | [Cloud Groups](https://attack.mitre.org/techniques/T1069/003/) |
| -ls | --list_searches | List all searches | [Discovery](https://attack.mitre.org/tactics/TA0007/) | [Cloud Service Discovery](https://attack.mitre.org/techniques/T1526/) | - |
| -ss | --save_searches | Save all searches locally | [Exfiltration](https://attack.mitre.org/tactics/TA0010/) | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020/) | - |
| -du | --delete_user | Delete a specific user | [Impact](https://attack.mitre.org/tactics/TA0040/) | [Account Access Removal](https://attack.mitre.org/techniques/T1531/) | - |
| -rs | --delete_searches | Delete all searches | [Impact](https://attack.mitre.org/tactics/TA0040/) | [Data Destruction](https://attack.mitre.org/techniques/T1485/) | - |
| -ms | --manipulate_searches | Manipulate all searches | [Impact](https://attack.mitre.org/tactics/TA0040/) | [Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/) | - |

## Examples

* To list all the options and switches use the -h switch:

```python splunkdefeat.py -h```

### PERSISTENCE

* Create a new user use the -au, -ap, and -ar switches:

```python splunkdefeat.py -au splunk-replicate -ap mypassword123 -ar admin```

* Modify a role with additional capabilities

```python splunkdefeat.py -ur admin -uc delete_by_keyword```
    
### DEFENSE EVASION

* Update the email for all search alert actions

```python splunkdefeat.py -ue noreply@example.com```

* Disable all searches

```python splunkdefeat.py -ds```

* Enable all searches
* 
```python splunkdefeat.py -es```

### CREDENTIAL ACCESS

* Brute force a user

```python splunkdefeat.py -sh splunk.example.com -sp 8089 -su sc_admin -sf```

### DISCOVERY

* List current user and role

```python splunkdefeat.py -lu```

* List all users and roles

```python splunkdefeat.py -la```

* List all roles and capabilities

```python splunkdefeat.py -lr```

* List all searches

```python splunkdefeat.py -ls```

### EXFILTRATION

* Download all saved searches locally

```python splunkdefeat.py -ss```

### IMPACT

* Delete a user

```python splunkdefeat.py -du user_a```

* Delete all searches

```python splunkdefeat.py -rs```
    
* Manipulate all searches

```python splunkdefeat.py -ms```

