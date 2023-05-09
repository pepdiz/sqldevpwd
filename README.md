# sqldevpwd
tool to decrypt sql developer connection passwords in a exported json file

## requirements
This program reads a json file with connections defined in Sql Developer. You can export connections as json file directly from Sql Developer or copy the file in file system, in windows it is located at c:\Users\<user>\AppData\Roaming\Sql Developer\Systemx.y.z.v.w\o.jdeveloper.db.connection\  where x.y.z.w.o is version number.

Tests are done with a json file exported with Sql Developer vesion 22.2.1 but it should work with any json file created with a Sql Developer 19.2 or greater.
