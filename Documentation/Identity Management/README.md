## Wordpress/Drupal Account Enumeration Using Cookies
Use the `--cookie-and-account` flag with `--wordlist` to enumerate Wordpress/Drupal CMS accounts on the target website. You can also use the optional `--threads` / `-t` flag (default: `50`):
```
./web-reGOn --cookie-and-account --wordlist [path to your wordlist] example.com
./web-reGOn --cookie-and-account --wordlist [path to your wordlist] example.com --threads 100
```

## Account Enumeration Based On Error Messages
Use the `--error-message-enum` flag with `--userlist` and `--passlist` to enumerate accounts on a target login page (e.g. `example.com/login`) based on error messages in the response (invalid username, invalid password, …). You can also use the optional `--threads` / `-t` flag (default: `50`):
```
./web-reGOn --error-message-enum --userlist [username list] --passlist [password list] example.com/login
./web-reGOn --error-message-enum --userlist users.txt --passlist passwords.txt example.com/login --threads 100
```

## Discovering Hidden Directories Using Cookies
Use the `--hidden-directories` flag with `--wordlist` to enumerate hidden directories on the target website. You can also use the optional `--threads` / `-t` flag (default: `50`):
```
./web-reGOn --hidden-directories --wordlist [path to your wordlist] example.com
./web-reGOn --hidden-directories --wordlist [path to your wordlist] example.com --threads 100
```

## Account Enumeration Based On 200 Status Code & Invalid User Error Message
Use the `--nonexistent-user-enum` flag with `--userlist` to enumerate accounts on a target login page using a username list and a fake password. The tool prints error messages when it receives HTTP `200`. You can also use the optional `--threads` / `-t` flag (default: `50`):
```
./web-reGOn --nonexistent-user-enum --userlist [username list] example.com/login
./web-reGOn --nonexistent-user-enum --userlist users.txt example.com/login --threads 100
```

## Account Enumeration Based On Status Code
Use the `--status-code-enum` flag with `--userlist` and `--passlist` to enumerate accounts on a target login page based on the received HTTP status code. You can also use the optional `--threads` / `-t` flag (default: `50`):
```
./web-reGOn --status-code-enum --userlist [username list] --passlist [password list] example.com/login
./web-reGOn --status-code-enum --userlist users.txt --passlist passwords.txt example.com/login --threads 100
```
