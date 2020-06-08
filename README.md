

## about SecretFinder

SecretFinder is a python script based on [LinkFinder](https://github.com/GerbenJavado/LinkFinder), written to discover sensitive data like apikeys, accesstoken, authorizations, jwt,..etc in JavaScript files. It does so by using jsbeautifier for python in combination with a fairly large regular expression. The regular expressions consists of four small regular expressions. These are responsible for finding and search anything on js files. 

The output is given in HTML or plaintext.

![main](https://i.imgur.com/D7MT2KL.png)


## help 

```
usage: SecretFinder.py [-h] [-e] -i INPUT [-o OUTPUT] [-r REGEX] [-b]
                       [-c COOKIE] [-g IGNORE] [-n ONLY] [-H HEADERS]
                       [-p PROXY]

optional arguments:
  -h, --help            show this help message and exit
  -e, --extract         Extract all javascript links located in a page and
                        process it
  -i INPUT, --input INPUT
                        Input a: URL, file or folder
  -o OUTPUT, --output OUTPUT
                        Where to save the file, including file name. Default:
                        output.html
  -r REGEX, --regex REGEX
                        RegEx for filtering purposes against found endpoint
                        (e.g: ^/api/)
  -b, --burp            Support burp exported file
  -c COOKIE, --cookie COOKIE
                        Add cookies for authenticated JS files
  -g IGNORE, --ignore IGNORE
                        Ignore js url, if it contain the provided string
                        (string;string2..)
  -n ONLY, --only ONLY  Process js url, if it contain the provided string
                        (string;string2..)
  -H HEADERS, --headers HEADERS
                        Set headers ("Name:Value\nName:Value")
  -p PROXY, --proxy PROXY
                        Set proxy (host:port)

```

## usage


