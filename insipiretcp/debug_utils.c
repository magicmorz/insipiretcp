#include "common.h"
void enable_sudo_debugging()
{
    // -----------start of sudo debug enabling
    /*
   The sole purprose of this code is to enable debugging with sudo in vscode.
   In order to make it work, make the following steps:
   1. add to launch.json:
       {
       "miDebuggerPath": "${workspaceFolder}/gdb_root.sh"
       }
   2. create file gdb_root.sh:
       #!/bin/bash
       SELF_PATH=$(realpath -s "$0")

       if [[ "$SUDO_ASKPASS" = "$SELF_PATH" ]]; then
       zenity --password --title="$1"
       else
       exec env SUDO_ASKPASS="$SELF_PATH" sudo -A /usr/bin/gdb $@
       fi
   3.  chmod +x gdb_root.sh
   4.  add the following code block to main with the needed #include-s
   */
    char *sudo_uid = getenv("SUDO_UID");
    if (sudo_uid)
        //setresuid(0, 0, atoi(sudo_uid));
        setresuid(0, 0, atoi(sudo_uid));

    printf("uid = %d\n", getuid());
    // -----------end of sudo debug enabling
}