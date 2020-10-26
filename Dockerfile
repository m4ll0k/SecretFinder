# usage:
# while read url; do docker run -t wfnintr/subfinder -i $url -o cli | tee -a js_results.txt;done < urls.txt
from python:alpine
LABEL maintainer="wfnintr@null.net"
RUN apk update && \
        apk add --virtual build-deps \
        build-base gcc python3-dev && \
        apk add libxml2-dev libxslt-dev && \
        wget https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/requirements.txt -qO - | pip3 install -r /dev/stdin && \
        wget https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/SecretFinder.py -qO /usr/local/bin/SecretFinder.py && \
        chmod +x /usr/local/bin/SecretFinder.py && \
        apk del build-deps
ENTRYPOINT [ "SecretFinder.py" ]
