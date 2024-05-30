# sqldevpwd
Tool to decrypt sql developer connection passwords in a exported json file.

Giving a connections json file and a decryption key it will show in stdout decrypted passwords for all connections in the file or those indicated by filtering.

## requirements
This program reads a json file with connections defined in Sql Developer. You can export connections as json file directly from Sql Developer or copy the file in file system, in windows it is located at c:\Users\\\<user>\AppData\Roaming\Sql Developer\Systemx.y.z.v.w\o.jdeveloper.db.connection\  where x.y.z.w.o is version number.

Tests are done with a json file exported with Sql Developer vesion 22.2.1 but it should work with any json file created with a Sql Developer 19.2 or greater.

Of course, you need python installed and also the required packages:
* json
* os
* re
* argparse
* base64
* hashlib
* Cryptodome
