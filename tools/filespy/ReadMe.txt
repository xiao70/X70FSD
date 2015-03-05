--------------------------------------------------
Utility: 	FileSpy 4.1.0.430
Author:		Laislav Zezula
Email:		ladik@zezula.net
WWW:            http://www.zezula.net/fstools.html
--------------------------------------------------

This ZIP archive includes the executable and debugging symbols for
the FileSpy tool, written as extension MS FileSpy (WDK 6001).

The tool does not have an installation, just run FileSpy.exe


Description
===========

The tool is designed to look and work similar like the famous
Filemon tool from Mark Russinovich (http://www.sysinternals.com).
The FileSpy's main purpose is for kernel developers.

Comparing to Filemon, it has some more functions

 - Mode advanced logging of IRPs and FastIOs
 - Advanced filtering by path, process, IRP code or FastIo code
 - Ability to monitor "exotic" file systems and network redirectors
   using its ability "attach by name"
 - Ability to monitor request from newly created processes
 - Ability to monitor newly mounted volumes
 - Ability to monitor FSD control volumes
   (e.g. to see IRP_MN_MOUNT_VOLUME)
 - Ability to log requests as they came or as they have been completed
 - Shows IOCTL codes of all WDK-documented and some undocumented
   IOCTL codes, together with IOCTL decoding (device type, method, etc)
 - Allows to use Minispy as kernel filter driver
 - Allows to use Filetrace as kernel filter driver
 - Allows to log USN journal


Some functions from Filemon are not implemented

 - Path properties and process properties
 - There is no "simple/advanced" output
 - History depth is not implemented
 - There is not help (yet, maybe later)


From the author:
================

I am sorry that I cannot make the sources available, but the kernel
part of this project is licensed and may not be freely distributed.
However, if anyone misses an useful function, let me know
and I'll implement it (as soon as I'll get time :-)

You may use the tool freely, whatever you need it for, regardles if
it is for personal or commercial use. I believe that many FSD and filter
developers will enjoy it, as it could help much in their work.


Warranty and Limitation of Liability:
=====================================
This program is provided as a service to the Windows system software development community
via OSR Online (www.osronline.com).  OSR Open Systems Resources, Inc not contributed to,
reviewed, or approved this program or any of the contents of this ZIP archive (except this file).

OSR Open Systems Resources, Inc. (OSR) expressly disclaims any warranty. THIS SOFTWARE IS PROVIDED
"AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING, WITHOUT LIMITATION, THE
IMPLIED WARRANTIES OF MECHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK ARISING
FROM THE USE OF THIS SOFTWARE REMAINS WITH YOU. OSR's entire liability and your exclusive remedy shall not
exceed the price paid for this material.  In no event shall OSR or its suppliers be liable for
any damages whatsoever (including, without limitation, damages for loss of business profit,
business interruption, loss of business information, or any other pecuniary loss) arising
out of the use or inability to use this software, even if OSR has been advised of the possibility
of such damages.  Because some states/jurisdictions do not allow the exclusion or limitation
of liability for consequential or incidental damages, the above limitation may not apply to you.
