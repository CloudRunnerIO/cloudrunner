CloudRunner.IO Command Line Tool and Server Agent
==================================================

Copyright (c) 2013-2014 CloudRunner.IO_

About
--------

CloudRunner.IO_ is a simple yet powerful framework for remote server management.
It's key features include:

* **Execute scripts** in your choice(bash, python, ruby, puppet and chef-solo recipes)

* Pass **environment variables** between servers and between different script languages (works for a limited number of languages, but can be extended with a plugin)

* Secure communication using **SSL** certificates

* **Fast and reliable**, using ZeroMQ as a transport backend(although a different backend can be used as a plugin)

* CloudRunner.IO_ also offers a commercial server, that performs a lot of useful tasks, including:

    * **User management**: assign roles for different users on different remote servers(how to impersonate an user on a server)
    * **Library management**: store, re-use scripts into different kind of stores - GitHub, ButBucket, SVN, Dropbox, Google Drive, Microsoft OneDrive, etc.
    * **Workflow management** - run multi-step scripts on different servers, with the ability to restart a script from arbitrary step, while keeping the environment context as it was in the first run.
    * **Web dashboard** for performing different operational tasks and for monitoring latest activities using filters.
    * Execution of **scheduled tasks** (using Cron)
    * **Triggers** - invoke stored script execution when a specific pattern appear in the activity logs.
    * **Highly customizable platform** - write your own plugins(in Python) for different kind of workflow management.
    * **Multi-tenancy** - supports isolated group of users who can access servers in a shared environment (including public clouds).
    * **HA and Multi-server routing** - install master servers in different locations(subnets, public clouds, etc.) and access all your servers from a single access point. No need to attach to different master server to access a remote server into directly inaccessible network. All you need is to allow the master servers to see each other.

    For more details see `www.cloudrunner.io
    <http://www.cloudrunner.io>`_ or ask for details at info@cloudrunner.io


Developing CloudRunner
-------------------------

CloudRunner CLI/Agent is an open-source project under the Apache 2 license. See the code at `www.github.com/cloudrunner
<http://www.github.com/cloudrunner/>`_. Everyone is welcome to contribute.


Documentation
====================

1. Command line tool installation
------------------------------------

First, install and configure the CLI tool with setting the needed certificates and paths::

    pip install cloudrunner
    cloudrunner-exec configure

`Note`: you might need to install some packages before installing with pip.
Cloudrunner depends on **ZeroMQ**, **M2Crypto** and **httplib2**. Install them using::

    pip install pyzmq
    pip install m2crypto
    pip install httplib2

`Note`: Use **python2** and **pip2(python2-pip)** for **Arch Linux**, CloudRunner only supports Python 2 at the moment, but this will change in future!

You can install them usign pip, but make sure you have already installed::

    * C++ compiler: gcc-c++ (CentOS, Fedora) or gcc (Arch Linux) or g++ (Debian, Ubuntu)
    * Python Dev libraries: python-devel (CentOS, Fedora) or python2 (Arch Linux) or python-dev (Debian)
    * OpenSSL Dev libraries: libssl-dev (Debian) openssl-devel (Centos) or openssl (Arch Linux)
    * Swig package (swig) on some Linuxes

Note: to be able to use autocomplete, do the following::

    pip install argcomplete
    source cloudrunner-autocomplete

Then run a simple script on your local machine::

    $ cloudrunner
    (bash)[local]$ hostname
    (bash)[local]$

    ========== JOB: @user local ==========
    user@localhost$
    my_computer_name

Get the CLI details(will be used in next step)::

    $ cloudrunner-exec details
    Certificate fingerprint        BF1AF11AFCA7E3D334A2AECD4B00B36635F560B0
    CLI cert CN                    my_computer_name


2. Server node installation
-------------------------------

Install and configure a the cloudrunner-node package::

    pip install cloudrunner
    cloudrunner-node configure

Make sure to open port 5552 on the server(this can be configured in config)

* using `ufw`::

    ufw allow 5552


* using iptables::

    iptables -I INPUT -p tcp --dport 5552 -j ACCEPT

Register the CLI details to allow access to this server using the details from the CLI above::

    cloudrunner-node register_cli -cn my_computer_name -fp BF1AF11AFCA7E3D334A2AECD4B00B36635F560B0

And finally start the server agent::

    # In debug mode:
    cloudrunner-node run

    # In daemon mode - use start|stop|restart with the --pidfile option to control the process
    cloudrunner-node start --pidfile cr-node.pid


3. Finally connect CLI with Server and start playing
-------------------------------------------------------

From CLI start the cloudrunner tool:: 

    $ cloudrunner
    (bash)[local]:

Let's do a simple test. Export a variable and print it::

    (bash)[local]: MY_VAR="the myvar content"

Then print it:: 

    (bash)[local]: echo $MY_VAR
    ========== JOB: @user local ==========
    user@localhost$
    the myvar content

And it's now time to run some code remotely, using the directive `switch` [server_name]::

    (bash)[local]: switch my_server_name

Someone might prefer to write in Python::

    (bash)[my_server_name]: lang python
    (python)[my_server_name]: import os
    (python)[my_server_name]: print "Printing the MY_VAR content: ", os.environ['MY_VAR']

One more thing: attach a file using the directive `attach_file`::

    (python)[my_server_name]: attach_file path/to/file

Let's print the file contents on the server:::

    (python)[my_server_name]: print "File contents:", open('path/to/file').read()

Click double [Enter] to execute::

    (python)[my_server_name]:
    (python)[my_server_name]:

And voila - here is the result::

    ========== JOB: @user 2390bfae ==========
    user@my_server_name$
    Printing the MY_VAR content: the myvar content
    File contents: [ -- the contents of the file follows --]

    (python)[my_server_name]:

Now you have the basic knowledge how to use the CloudRunner.IO_ **CLI** and **Server agent**.
Use your imagination (and the `help` command of course) to do more and more!

.. _CloudRunner.IO: http://www.cloudrunner.io