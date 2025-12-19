## Wordpress/Drupal Account Enumeration Using Cookies
Use the `--cookie-and-account` flag with `--wordlist` to enumerate Wordpress/Drupal CMS accounts of your target website. You can also use the optional `--threads` flag to set threads number:
```
./linux-reGOn --cookie-and-account [domain name] --wordlist [path to your wordlist] --threads [number of threads]
```

## Account Enumeration Based On Error Messages
Use the `--error-message-enum` flag with `--wordlist` to enumerate accounts of your target login page (e.g, example.com/login) based on error messages on recieved response (e.g, invalid username, invalid password, ...). You can also use the optional `--threads` flag to set threads number:
```
./linux-reGOn --error-message-enum [login page] --wordlist [path to your wordlist] --threads [number of threads]
```

## Discovering Hidden Directories Using Cookies
Use the `--hidden-directories` flag with `--wordlist` to enumerate hidden directories of your target website. You can also use the optional `--threads` flag to set threads number:
```
./linux-reGOn --hidden-directories [domain name] --wordlist [path to your wordlist] --threads [number of threads]
```

## Account Enumeration Based On 200 status code & Invalid User Error Message
Use the `--nonexistent-user-enum` flag with `--wordlist` to enumerate accounts of your target login page (e.g, example.com/login) based on error messages on recieved response with a fake password (e.g, invalid username, user not found, ...). This code prints the error messages only when it recieves 200 status code. You can also use the optional `--threads` flag to set threads number:
```
./linux-reGOn --nonexistent-user-enum [login page] --wordlist [path to your wordlist] --threads [number of threads]
```

## Account Enumeration Based On Status Code
Use the `--status-code-enum` flag with `--wordlist` to enumerate accounts of your target login page (e.g, example.com/login) based on recieved status code. You can also use the optional `--threads` flag to set threads number:
```
./linux-reGOn --status-code-enum [domain name] --wordlist [path to your wordlist] --threads [number of threads]
```