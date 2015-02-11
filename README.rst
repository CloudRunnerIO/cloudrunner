CloudRunner.IO Agent tool and API
==================================

Copyright (c) 2013-2015 CloudRunner.IO_

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
    * **Multi-tenancy** - supports isolated group of users who can access servers in a shared environment (including public clouds).
    * **HA and Multi-server routing** - install master servers in different locations(subnets, public clouds, etc.) and access all your servers from a single access point. No need to attach to different master server to access a remote server into directly inaccessible network. All you need is to allow the master servers to see each other.
    * **Highly customizable platform** - write your own plugins(in Python) for different kind of workflow management.

    For more details see `www.cloudrunner.io
    <http://www.cloudrunner.io>`_ or ask for details at info@cloudrunner.io


Developing CloudRunner
-------------------------

CloudRunner Agent is an open-source project under the Apache 2 license. See the code at `www.github.com/cloudrunner
<http://www.github.com/cloudrunner/>`_. Everyone is welcome to contribute.


Documentation
====================

1. CloudRunner.IO agent
------------------------------------

Install and configure the Agent for use with CloudRunner.IO Master server::

    pip install cloudrunner
    cloudrunner-node configure --org=MY-API-KEY -i NODE_NAME

`Note`: if **NODE_NAME** is skipped - the machine hostname will be used instead.

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


2. CloudRunner.IO Python API
-------------------------------

To use the Python `CloudRunner.IO REST API`_ client - install cloudrunner using `pip`::

    pip install cloudrunner

Instantiate the client object::

    from cloudrunner.api.client import *

    client = Client('myusername', 'my_api_token')

Now you are ready to load/modify data on the server. Lets start with just listing
the repositories in the Library:

    repos = client.library.repositories.list()
    print repos

Returns an array of repositories::

    [<cloudrunner.api.library.Repository at 0x7fb4f5e75fd0>,
     <cloudrunner.api.library.Repository at 0x7fb4f6dd7410>,
     <cloudrunner.api.library.Repository at 0x7fb4f5e777d0>,
     <cloudrunner.api.library.Repository at 0x7fb4f5e77890>]


You can use the returned objects and get their properties::

    print repos[0].name

    >> "RepoName"

Lets see the contents of the root folder in first repo::

    print client.library.browser.list(repos[0].name, '/')

    [<cloudrunner.api.library.Folder at 0x7f046c81cd90>,
     <cloudrunner.api.library.Script at 0x7f046c81ce10>,
     <cloudrunner.api.library.Script at 0x7f046c81cb90>,
     <cloudrunner.api.library.Script at 0x7f046c81cc10>,
     <cloudrunner.api.library.Script at 0x7f046c81cc50>,
     <cloudrunner.api.library.Script at 0x7f046c81cc90>,
     <cloudrunner.api.library.Script at 0x7f046c81cbd0>]

Now lets make a search for a specific log::

    logs = client.logs.search.list(filter='my favourite pattern')
    print logs

Fortunatelly, we get some results::

    [<cloudrunner.api.logs.Log at 0x7f046c81cfd0>,
    <cloudrunner.api.logs.Log at 0x7f046c81ca10>,
    <cloudrunner.api.logs.Log at 0x7f046c81cb10>,
    <cloudrunner.api.logs.Log at 0x7f046c81cb50>,
    <cloudrunner.api.logs.Log at 0x7f046c81f090>,
    <cloudrunner.api.logs.Log at 0x7f046c81f450>]

To retrieve the information for a log, we will load it using::

  log = client.logs.get.item(logs[0])
  print log

  >> <cloudrunner.api.logs.Log object at 0x7f046c7b5310>

To get the runs under a specific workflow in a Log::

  print log.workflow[0].runs[0]

  << [<cloudrunner.api.base.ApiObject at 0x7f046c7b5d90>]

  print log.workflow[0].runs[0].uuid

  << u'ff57f0b8ac1a426783d5763626be07cb'

We want to see the output from the first run in the first workflow::

    logs = client.logs.output.item(l.workflows[0].runs[0].uuid)
    print logs

    >> [<cloudrunner.api.logs.Log at 0x7f046d08f390>]

    print logs[0].screen

    >> <cloudrunner.api.base.ApiObject object at 0x7f046c7b5f90>

    print logs[0].screen._values

    >> {u'NODE_NAME': {u'lines': [[1423063412.399, [u'OUTPUT FROM MY SCRIPT EXECUTION'], u'O']]}}

In fact, we can load the node data directly from the screen object::

    print logs[0].screen.NODE_NAME.lines

    >> [[1423063412.399, [u'OUTPUT FROM MY SCRIPT EXECUTION'], u'O']]

We can also get the currently registered nodes in our account::

    nodes = client.nodes.nodes.list()
    print nodes

    >> [<cloudrunner.api.nodes.Node at 0x7f8664b10250>,
     <cloudrunner.api.nodes.Node at 0x7f86645151d0>,
     <cloudrunner.api.nodes.Node at 0x7f8664515050>]

    node = nodes[0]
    print node.name

    >> NODE_NAME

    print node.meta._values

    >> {
         u'ARCH': u'x86_64',
         u'AVAIL_MEM': 767,
         u'CPUS': None,
         u'CPU_CORES': 1,
         u'CRN_VER': u'1.1.0',
         u'DIST': u'CentOS',
         u'HOST': u'NODE_NAME',
         u'ID': u'NODE_NAME',
         u'MASTER_IP': u'192.168.1.1',
         u'OS': u'Linux',
         u'PRIVATE_IP': [u'10.1.1.1', u'127.0.0.1'],
         u'PUBLIC_IP': [u'54.1.1.1'],
         u'RELEASE': u'2.6.32-431.29.2.el6.x86_64',
         u'SERVER_NAME': u'NODE_NAME',
         u'TOTAL_MEM': 992
      }

    print node.joined_at

    >> u'2015-01-28 10:39:44'

.. _CloudRunner.IO: http://www.cloudrunner.io
.. _CloudRunner.IO REST API: http://api.cloudrunner.io/docs

