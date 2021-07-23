- [IDArling](#idarling)
  - [Overview](#overview)
  - [Releases](#releases)
  - [Installation](#installation)
    - [Server-side](#server-side)
    - [Client-side](#client-side)
    - [Dedicated server](#dedicated-server)
  - [Connection to server and usage](#connection-to-server-and-usage)
  - [Features](#features)
    - [General features](#general-features)
    - [Implementation details](#implementation-details)
    - [Known changes already synced by IDArling](#known-changes-already-synced-by-idarling)
    - [Known changes not currently synced by IDArling](#known-changes-not-currently-synced-by-idarling)
- [Thanks](#thanks)
- [Authors](#authors)
-------------------------------------------------------------------------------

# IDArling

<p align="center">
    <img src="https://i.imgur.com/9Vxm0Fn.png" />
</p>

## Overview

IDArling is a collaborative reverse engineering plugin for [IDA Pro](https://www.hex-rays.com/products/ida/)
and [Hex-Rays](https://www.hex-rays.com/products/decompiler/index.shtml). It
allows to synchronize in real-time the changes made to a database by multiple IDA
users, by connecting together different instances of IDA Pro.

It works by hooking certain events generated by one user in IDA and 
propagating the detected changes to other IDA users through a server architecture.
It supports working from a given snapshot with changes done by other IDA users 
re-applied to every other user loading the same snapshot.

## Releases

This project is under active development. Feel free to send a PR if you would
like to help! :-)

It is stable enough to be used in its current state, but be aware of the features
IDArling does not support before using it so you can save a new snapshot to work
around the limitations (see below).

Note: this is a fork of [https://github.com/IDArlingTeam/IDArling](IDArlingTeam).
The IDArlingTeam version supports IDA 7.0+ and Python2/3. Our fork only supports
IDA 7.4+ and Python 3 but has more features.

Note: if you migrate from IDArlingTeam installation, you are advised to backup
your old IDBs and start from a fresh new server. This is because we had to break
backward compability to add certain features.

## Installation

There are two different use cases:

* IDA Pro used for both the IDArling client (IDA Pro plugin) and IDArling server, 
  by using the "Integrated Server". You can ignore the "Server-side" installation.
* IDA Pro used for the IDArling clients and a remote IDArling server. You can refer
  to the "Server-side" and "Client-side" installation

### Server-side

Python3 is required.

The IDArling server is run on a remote system from the command-line. Generally
simply running `./idarling.py` is sufficient. A more advanced invocation is:

```
python3 idarling_server.py -h 192.168.1.1 -p 12345 --no-ssl -l DEBUG
```

### Client-side

IDA Pro 7.4+ with IDA Python 3 is supported.

Install the IDArling client into the IDA plugins folder.

- Copy `idarling_plugin.py` and the `idarling` folder to the IDA plugins folder.
    - On Windows, the folder is at `C:\Program Files\IDA 7.x\plugins`
    - On macOS, the folder is at `/Applications/IDA Pro 7.x/idabin/plugins`
    - On Linux, the folder may be at `~/ida-7.x/plugins/`
- Alternatively, you can use the IDAUSR folder such as 
  `C:\Users\<user>\AppData\Roaming\Hex-Rays\IDA Pro\plugins` on Windows.
- Alternatively, you can use the "easy install" method by copying the following
line into the console:

```
import urllib2; exec(urllib2.urlopen('https://raw.githubusercontent.com/fidgetingbits/IDArling/master/easy_install.py')).read()
```

### Dedicated server

To enable the dedicated server, you can choose "Dedicated Server" after right-clicking
the IDArling widget located in the status bar.

The dedicated server requires PyQt5, which is integrated into IDA. If you're
using an external Python installation, we recommand using Python 3, which offers
a pre-built package that can be installed with a simple `pip install PyQt5`.

## Connection to server and usage

Open the "Settings" dialog accessible from the right-clicking the IDArling widget located
in the status bar. Show the servers list by clicking on the "Network Settings"
tabs and add your server to it. Connect to the server by clicking on it after 
right-clicking the widget again. Finally, you should be able to access the
following menus to upload or download a database:

* File --> Open from server
* File --> Save to server

![](img/open_from_server.png)

## Features

### General features

The main features of IDArling (advertised originally) are:

* hooking general user events
* structure and enumeration support
* Hex-Rays decompiler syncing
* replay engine and auto-saving
* database loading and saving
* interactive status bar widget
* user cursors (instructions, functions, navbar)
* invite and following an user moves
* dedicated server using Qt5
* integrated server within IDA
* LAN servers discovery
* following an user moves in real time

### Implementation details

In order to understand what change is actually synced vs not synced, it is 
worth mentioning some implementation details.

We like to define the following terms in the IDArling jargon:

- group: a group correspond to a researched topic such as a given CVE, malware family,
  etc. regrouping several projects
- project: a project correspond to a given file to analyse (i.e. unique SHA-256 hash)
- database: a database is a snapshot of an IDB as a given time. It is 
  used as a baseline to apply any change made from this snapshot by any other 
  IDA user

In general, the first thing is to create a group for the research topic you are
starting. Then, you create a project to analyse a given file with a unique hash (e.g. `ntoskrnl.exe`
on Windows 10 1809 x64 from May 2019) and then you create one initial database.
All the changes made for this IDB can leave in the same database as long as all
the changes you do are synced. However, if there are some major changes that are
not synced by IDArling, you need to create an additional database to save them
and all users SHOULD then use the latest database.

In general, it is better to always start from the latest database (i.e. 
snapshot) for a given project when you start working from the IDArling 
server, except if you know what you are doing.

If you locally update your IDB with a new type in IDA and save it to a 
new snapshot, you are NOT REQUIRED to then close and open the new snapshot 
that you saved to the database. You can keep working from your existing 
already-opened snapshot. The only exception to this would be if someone else 
simultaneously updated their own IDB and uploaded a new snapshot.

### Known changes already synced by IDArling

In general, the changes applied to a given snapshot are retrieved the next 
time you open the latest snapshot as the events will be propagated to the 
base IDB.

* Syncs variable names in Hex-Rays
* Syncs comments in Hex-Rays
* Syncs function prototype edits in both IDA and Hex-Rays
* Syncs integer type (hex / integer / binary / enum) changes in both IDA and Hex-Rays
* Manually creating an enum and pasting in the code will actually sync across
 IDBs
 
Note: the above list is not up-to-date and needs to be updated.

### Known changes not currently synced by IDArling

These changes typically require you to create a new database (i.e. snapshot, as
explained above) so you don't lose your changes. It is typically the case for
actions that do not generate events that IDArling can catch and propagate.

We are tracking in 2 categories the issues on our github repository:

* [Fatal non-propagated features](https://github.com/fidgetingbits/IDArling/labels/fatal%20non-propagated%20feature): 
  These are features of IDA that are not propagated over IDArling that 
  potentially corrupt the IDB. An example would be if new types were not created 
  properly. If it were the case, it means all actions that depend on the types 
  existing would be broken, e.g. decompiler/disassembler output that relies on 
  these structures, etc.
* [Non-propagated features](https://github.com/fidgetingbits/IDArling/issues?q=is%3Aissue+is%3Aopen+label%3A%22non-propagated+feature%22):
  These are features of IDA that are not propagated over IDArling but do not 
  risk corrupting the IDB. An example would be if bookmarks were not propagated.
  It is not the case but if it were, only bookmarks would be missing and all the
  other contents from the IDBs would still be sane.

Note that some of the issues have been marked as "won't fix" and closed as atm
we don't think they are worth fixing but feel free to add comments if you disagree.

# Thanks

This project is inspired by [Sol[IDA]rity](https://solidarity.re/). It started
after contacting its authors and asking if it was ever going to be released to
the public. [Lighthouse](https://github.com/gaasedelen/lighthouse) source code
was also carefully studied to understand how to write better IDA plugins.

* Previous plugins, namely [CollabREate](https://github.com/cseagle/collabREate),
[IDASynergy](https://github.com/CubicaLabs/IDASynergy),
[YaCo](https://github.com/DGA-MI-SSI/YaCo), were studied during the development
process;
* The icons are edited and combined versions from the sites [freeiconshop.com](http://freeiconshop.com/)
and [www.iconsplace.com](http://www.iconsplace.com).

Thanks to Quarkslab for allowing this release.

# Authors

* Alexandre Adamski <<neat@idarling.re>>
* Joffrey Guilbon <<patate@idarling.re>>
* Cedric Halbronn ([@saidelike](https://twitter.com/saidelike))
* Aaron Adams ([@FidgetingBits](https://twitter.com/fidgetingbits))

If you have any questions not worthy of a bug report, feel free to ping us at
[#idarling on freenode](https://kiwiirc.com/client/irc.freenode.net/idarling)
and ask away.