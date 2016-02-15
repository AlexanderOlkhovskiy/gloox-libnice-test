### A proof-of-concept [libnice](http://nice.freedesktop.org/wiki/)/[gloox](https://camaya.net/gloox/)-based [Interactive Connectivity Establishment (ICE)](http://tools.ietf.org/html/rfc5245) test application
This application is supposed to be used as a proof-of-concept example of one of possible ICE implementations for 0 A.D. RTS game (see the related ticket: [#2305 UDP Hole Punching / NAT Traversal](http://trac.wildfiregames.com/ticket/2305)).

libnice is responsible for ICE logic (candidate gathering, selecting the nominated pair, keeping the connection alive).  
gloox is used for signaling.

#### Current state
The application basically works (was tested locally and over network (at revision a367b12)).  
Code requires some fixes, cleanup and refactoring.

#### Dependencies
The application depends on gloox and libnice (which depends on glib).  
It was tested with gloox-1.0.13 and libnice-0.1.13.

#### Usage
```
./gloox_libnice host <hostJid> <hostPassword>
./gloox_libnice join <clientJid> <clientPassword> <hostJid>
```
Note: hostJid should have a resource (and it should be the same in both application instances.  
Example:
```
./gloox_libnice host host@example.com/gloox password
./gloox_libnice join client@example.com/gloox password host@example.com/gloox
```

Application can be executed with `G_MESSAGES_DEBUG=all NICE_DEBUG=all` variables to produce debug output.  
Also gloox log level can be changed in the source.

#### License
gloox is GNU GPLv3, which makes this application restricted to the same license terms (see gpl-3.0.txt).  
libnice is dual-licensed Mozilla Public License 1.1 / GNU LGPL 2.1, so doesn't impose additional license restrictions (and doesn't conflict with the gloox license).

