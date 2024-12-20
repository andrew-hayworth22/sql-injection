# SQL Injection

A demonstration of SQL injection vulnerabilites as well as a secured version.

This project is a simple authentication server that allows users to create and login to accounts. Associated to each user account is a set of data (only created through database seeding).

## Running the Server

To run the server, run the following command:

``` go run . ```

By default, the server will contain SQL injection vulnerabilities. To run a fixed version of the server, run this command:

``` go run . --secure ```

You can switch between these modes while the server is running by clicking on the state link on the top left corner of the screen.

## Screen Breakdown

1. **Register:** Allows users to create accounts with a username and password. If the account creation is successful, they will be taken to the login screen.

*Note: Passwords must be at least 6 characters* 

2. **Login:** Allows users to provide their credentials and access their data in the system.

3. **Status:** Allows users to view a snapshot of what the database currently holds for troubleshooting purposes.

4. **Reset DB:** Allows users to reset the database to its initial state.

## Account Data

Due to the mitigation strategies used in the secure version of the server, accounts created in vulnerable mode cannot be accessed using secure mode and vice versa.

The following seeded logins work in vulnerable mode:
- andy (vulnerable)
    - Password = andy_pass
- jeff (vulnerable)
    - Password = jeff_pass

The following seeded logins work in secure mode:
- sally (secure)
    - Password = sally_pass
- anna (secure)
    - Password = anna_pass

## Potential SQL Injection Attacks

The following inputs to the "Login" screen when the server is in "Vulnerable" mode highlight major SQL injection vulnerabilities. Any password will work for these attacks.

## Attack 1: Dropping Tables

Username: ``` '; drop table users; /* ```

With these inputs, any user can drop the entire user table. This not only loses all of that sensitive data, but also renders the server unusable due to query errors.

## Attack 2: Unauthorized Data Access

Username: ``` andy (vulnerable)' or '' = ' ```

With these inputs, any user can access any account they want (just update the username in the beginning of the username field). This provides unauthorized access to the system.

## Attack 3: Unauthorized Data Modification

Username: ``` '; update data set data = 'YOU HAVE BEEN HACKED LOL'; /* ```

This attack updates all of the data in the system to the text "YOU HAVE BEEN HACKED LOL," exposing the unauthorized tampering of data. This attack can be tweaked and extended even further. The following input will update all data associated with user's of a particular name:

Username: ``` ';update data set data = 'HEY ANDY, THIS IS AN ATTACK' from (select id from users where username = 'andy') as u where user_id = u.id;/* ```

## Mitigation Strategies

To solve these issues and protect the server against SQL injection attacks (along with some extra protections), the secure version of this server implements these mitigation strategies:

- Prepared SQL statements
- Input sanitization and validation
- Storing password hashes
- Storing encrypted usernames