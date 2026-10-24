# User Inventory Notes

input: a list of users authorized to be able to ssh into the box, and a list of boxes and their logins
output: a list `user,password` pairs 

this script should use coordinate to run multiple scripts
+ inventory
  - this should list out all of the users that can access the box, with the following information separated by ascii character 0x09, horizontal tab
  - hostname or domain, username, privilege level, login enabled, blank, TRUE, blank, blank
  - this information should get printed to standard out

+ ensure access
  - this should lock the root account password
  - make the root user nologin
  - ensure there is a group that has root privileges in the sudo or doas config
  - create a new user with admin privileges
  - allow ssh as that user
  - output the password of the newly created user

+ credential changing
  - this should take in a list of local users that are authorized to log in and have a shell on the box, as well as their privilege level, in a format similar to the output of the last script
  - it should then enumerate all of the local users and if they are not authorized changes their shell to be nologin and lock their password
  - generates a secure unique password for each authorized user and ensures their groups are correct
  - outputs the following information separated by ascii character 0x09, horizontal tab
  - hostname, username, privilege level, login enabled, password, FALSE, blank, blank

the overall script should run these scripts one after the other and do some processing between
+ run script 1
+ make note of any unauthorized users and print them out
+ run script 2
+ generate a list of authorized local users and their authorities from the input
+ check with the person running the script to see if any users can be safely deleted
+ run script 3
+ output a list of users with the following information seperated by ascii character 0x09, horizontal tab
  - hostname or domain,# User Inventory Notes

input: a list of users authorized to be able to ssh into the box, and a list of boxes and their logins
output: a list `user,password` pairs 

this script should use coordinate to run multiple scripts
+ inventory
  - this should list out all of the users that can access the box, with the following information separated by ascii character 0x09, horizontal tab
  - hostname or domain, username, privilege level, login enabled, blank, TRUE, blank, blank
  - this information should get printed to standard out

+ ensure access

+ credential changing
  - this should take in a list of local users that are authorized to log in and have a shell on the box, as well as their privilege level, in a format similar to the output of the last script
  - it should then enumerate all of the local users and if they are not authorized changes their shell to be nologin and lock their password
  - generates a secure unique password for each authorized user and ensures their groups are correct
  - outputs the following information separated by ascii character 0x09, horizontal tab
  - hostname, username, privilege level, login enabled, password, FALSE, blank, blank
