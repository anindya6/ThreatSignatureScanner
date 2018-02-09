First, we'll create a root-accessible only file. Let's call it "virus.txt" and has many common virus signatures on it.

sudo chown root:root virus.txt
sudo chmod 700 virus.txt

This file is readable only by root (sudo vim virus.txt)

Now we need to set root privileges for our file read service (if it hasn't been done before)

gcc frs.c -lseccomp -o frs

The frs executable needs to be owned by root and needs to have its setuid bit set.

sudo chown root:root frs
sudo chmod +s frs

Now frs is able to set its uid to root to access virus.txt with simply ./frs (as opposed to sudo ./frs, if setuid was not in use).

Now please refer to Screenshot "setuid example":
"wow.txt" - infected file accessible only by root.

Case 1: File Read Service called as sudo ./frs
The FRS in this case manages to read the file, as it has been run by root.

Case 2: File Read Service called as ./frs (./frsroot in the shown example) but with setuid bit set with chmod.

Case 3: Copy of File Read Service without setuid coded within program but with root ownership and setuid bit set called. Unable to read file, shows "Clean"