/*
Show_dump 0.2

    Copyright 2004,2005,2006,2007 Luigi Auriemma

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

This function, optimized for performace, shows the hex dump of a buffer and
places it in a stream

Usage:
        show_dump(buffer, buffer_length, stdout);
        show_dump(buffer, buffer_length, fd);
*/

#include <string.h>
#include <stdio.h>


void show_dump(int left, unsigned char *data, unsigned int len, FILE *stream) {
    static const char   hex[] = "0123456789abcdef";
    int                 rem;
    unsigned char       leftbuff[80],
                        buff[67],
                        chr,
                        *bytes,
                        *p,
                        *limit,
                        *glimit = data + len;

    memset(buff + 2, ' ', 48);
    memset(leftbuff, ' ', sizeof(leftbuff));

    while(data < glimit) {
        limit = data + 16;
        if(limit > glimit) {
            limit = glimit;
            memset(buff, ' ', 48);
        }

        p     = buff;
        bytes = p + 50;
        while(data < limit) {
            chr = *data;
            *p++ = hex[chr >> 4];
            *p++ = hex[chr & 15];
            p++;
            *bytes++ = ((chr < ' ') || (chr >= 0x7f)) ? '.' : chr;
            data++;
        }
        *bytes++ = '\n';

        for(rem = left; rem >= sizeof(leftbuff); rem -= sizeof(leftbuff)) {
            fwrite(leftbuff, sizeof(leftbuff), 1, stream);
        }
        if(rem > 0) fwrite(leftbuff, rem, 1, stream);
        fwrite(buff, bytes - buff, 1, stream);
    }
}

