Setting up my program!

compile individual programs (mp.c, st.c, tdu.c, frs.c)
mp.c = main process
st.c = threat scanner
tdu.c = threat update service
frs.c = file read service

Link -lseccomp libraries to each of them.

Set root ownership to frs object and set its uid. Follow the other readme to do this.

st.c, tdu.c and frs.c stays on a MSG_DONTWAIT loop to get its first message from mp.c, so the order of starting the programs is unimportant. 
However, make sure to restart st.c and frs.c every time you restart the mp.c service (it doesn't manually terminate).

Files to be scanned can be sent as command line arguments to mp.c, example: ./mp normal1.txt normal2.txt normal3.txt virus.txt

Design Choices:
1) st.c,tdu.c,frs.c run a MSG_DONTWAIT loop to make the order of execution of the programs unimportant, because mp.c needs to receive a message from these services first to get the server address. If they did not run this loop, they would need to be executed in a particular order.
2) mp.c binds sockets in the order of waiting for a particular service - this is done so that the received messages from the other sockets don't keep piling up in the buffer, as it will mess up the execution of later parts of the program.
3) Occasionally (it happened to me once out of 30 runs or more) you might have the wrong information transferred because of the MSG_DONTWAIT loop, which is why both st.c and frs.c keep printing the data they received.

Refer to the screenshot "setuid example" and the other readme to see how the program works.

My program works! Please contact me if something doesn't go right!

References:
[1] Linux man pages
[2] https://www.programminglogic.com/sockets-programming-in-c-using-udp-datagrams/
[3] Stack Overflow
[4] https://www.gnu.org/software/libc/manual/html_node/Setuid-Program-Example.html
