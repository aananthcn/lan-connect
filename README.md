# lan-connect
LanConnect will help connect devices securely and talk to each other with in a LAN.
It is composed of following classes

 1. SecureSocket - the name explains everything
 2. LcFinder - does find all devices in a LAN
 3. EasyJson - a helper class to parse json files
 4. LanConnect - the main class that manages modes and protocol


## What does LanConnect do internally?
It opens 2 sockets (server & client) in each thread. The server thread looks for
incoming connections and once established it helps to answer command, queries and
mode managment needed by the client. The client thread scans for servers and tries
to connect to all other servers (one at a time).


## What are different LanConnect modes supported?
The LanConnect at present supports following modes:
 1. Command & Query Mode (default)
 2. File Transfer Mode
 3. _Audio Streaming Mode (TBD)_


## What is LanConnect protocol?
By default the client and server will be in "Command & Query Mode". In this mode
the server shall initiates a query and client shall respond to it. And the again
server shall initiate commands and client shall responds to it.

It is server drive protocol (different from a browser - server). Details of this protcol
is inside the brain of Aananth C N, which is (un)fortunately controlled by the creator
of this world, hence will be updated in this page as on when the creator communicates
with this idiot.


### What are different queries supported?
 1. Get device info
 2. Get device supported modes
 3. List all files that can be shared

### What are different commands supported?
 1. Enter File Transfer Mode and send file xyz
 2. Enter File Transfer Mode and receive file xyz


# LICENSE
This work is relased under Mozilla Public Licese v2.0
