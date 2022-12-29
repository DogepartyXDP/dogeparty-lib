FROM ubuntu:18.04

#MAINTAINER Dogeparty Developers <dev@dogeparty.net>

# Install common dependencies
RUN apt-get update && apt-get install -y apt-utils ca-certificates wget curl git mercurial \
    python3 python3-dev python3-pip python3-setuptools python3-appdirs \
    build-essential vim unzip software-properties-common sudo gettext-base \
    net-tools iputils-ping telnet lynx locales

# Upgrade pip3 to newest
RUN pip3 install --upgrade pip

# Set locale
RUN dpkg-reconfigure -f noninteractive locales && \
    locale-gen en_US.UTF-8 && \
    /usr/sbin/update-locale LANG=en_US.UTF-8
ENV LC_ALL en_US.UTF-8

# Set home dir env variable
ENV HOME /root

COPY . /dogeparty-lib
WORKDIR /dogeparty-lib
RUN pip3 install -r requirements.txt
RUN python3 setup.py develop
RUN python3 setup.py install_apsw

# Install dogeparty-cli
# NOTE: By default, check out the dogeparty-cli master branch. You can override the BRANCH build arg for a different
# branch (as you should check out the same branch as what you have with dogeparty-lib, or a compatible one)
ARG CLI_BRANCH=master
ENV CLI_BRANCH ${CLI_BRANCH}
RUN git clone -b ${CLI_BRANCH} https://github.com/DogepartyXDP/dogeparty-cli.git /dogeparty-cli
#RUN git clone -b ${CLI_BRANCH} git@github.com:DogepartyXDP/dogeparty-cli.git /dogeparty-cli
WORKDIR /dogeparty-cli
RUN pip3 install -r requirements.txt
RUN python3 setup.py develop

# Additional setup
COPY docker/server.conf /root/.config/dogeparty/server.conf
COPY docker/start.sh /usr/local/bin/start.sh
RUN chmod a+x /usr/local/bin/start.sh
WORKDIR /

EXPOSE 4005 14005

# NOTE: Defaults to running on mainnet, specify -e TESTNET=1 to start up on testnet
ENTRYPOINT start.sh ${DOGE_NETWORK} ${NO_BOOTSTRAP}
