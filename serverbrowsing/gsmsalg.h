/*
GSMSALG 0.3.3
by Luigi Auriemma
e-mail: aluigi@autistici.org
web:    aluigi.org


INTRODUCTION
============
With the name Gsmsalg I define the challenge-response algorithm needed
to query the master servers that use the Gamespy "secure" protocol (like
master.gamespy.com for example).
This algorithm is not only used for this type of query but also in other
situations like the so called "Gamespy Firewall Probe Packet" and the
master server hearbeat that is the challenge string sent by the master
servers of the games that use the Gamespy SDK when game servers want to
be included in the online servers list (UDP port 27900).


HOW TO USE
==========
The function needs 4 parameters:
- dst:     the destination buffer that will contain the calculated
           response. Its length is 4/3 of the challenge size so if the
           challenge is 6 bytes long, the response will be 8 bytes long
           plus the final NULL byte which is required (to be sure of the
           allocated space use 89 bytes or "((len * 4) / 3) + 3")
           if this parameter is NULL the function will allocate the
           memory for a new one automatically
- src:     the source buffer containing the challenge string received
           from the server.
- key:     the gamekey or any other text string used as algorithm's
           key, usually it is the gamekey but "might" be another thing
           in some cases. Each game has its unique Gamespy gamekey which
           are available here:
           http://aluigi.org/papers/gslist.cfg
- enctype: are supported 0 (plain-text used in old games, heartbeat
           challenge respond, enctypeX and more), 1 (Gamespy3D) and 2
           (old Gamespy Arcade or something else).

The return value is a pointer to the destination buffer.


EXAMPLE
=======
  #include "gsmsalg.h"

  char  *dest;
  dest = gsseckey(
    NULL,       // dest buffer, NULL for auto allocation
    "ABCDEF",   // the challenge received from the server
    "kbeafe",   // kbeafe of Doom 3 and enctype set to 0
    0);         // enctype 0


LICENSE
=======
    Copyright 2004,2005,2006,2007,2008 Luigi Auriemma

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA

    http://www.gnu.org/licenses/gpl.txt
*/


unsigned char *gsseckey(
  unsigned char *dst,
  unsigned char *src,
  unsigned char *key,
  int           enctype);