
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

## Installation

SecretFinder supports Python 3.

```
$ git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
$ cd secretfinder
$ python -m pip install -r requirements.txt or pip install -r requirements.txt
$ python SecretFinder.py
```

## Usage

- Most basic usage to find the sensitive data with default regex in an online JavaScript file and output the HTML results to results.html:

`python3 SecretFinder.py -i https://example.com/1.js -o results.html`

- CLI/STDOUT output (doesn't use jsbeautifier, which makes it very fast):

`python3 SecretFinder.py -i https://example.com/1.js -o cli`

- Analyzing an entire domain and its JS files:

`python3 SecretFinder.py -i https://example.com/ -e`

- Ignore certain js file (like external libs) provided by `-g --ignore`

`python3 SecretFinder.py -i https://example.com/ -e -g 'jquery;bootstrap;api.google.com'`

- Process only certain js file provided by `-n --only`:

`python3 SecretFinder.py -i https://example.com/ -e -n 'd3i4yxtzktqr9n.cloudfront.net;www.myexternaljs.com'`

- Use your regex:

`python3 SecretFinder.py -i https://example.com/1.js -o cli -r 'apikey=my.api.key[a-zA-Z]+'`

- Other options: add headers,proxy and cookies:

``python3 SecretFinder.py -i https://example.com/ -e -o cli -c 'mysessionid=111234' -H 'x-header:value1\nx-header2:value2' -p 127.0.0.1:8080 -r 'apikey=my.api.key[a-zA-Z]+'``
