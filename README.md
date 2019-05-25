# Design
## Server
camouflage
sniff
filter
interpret
encrypt
respond

## client
get input
encrypt
send message
wait for response
decrypt
display response

# Pseudo
## server
confirm root/fix
interpret command line
output usage on error|help & exit
camouflage backdoor
while not 'quit'
    sniff packets
        authenticate packets
            decrypt packets
                interpret message
                do commmand
                send results

## client
confirm root/fix
interpret command line
display notification
while entry not blank line
    encrypt command
    send command
        open connection
        send message
        close connection
    wait for response
        listen on port
        decrypt response
        display response
        close connection
exit

# Testing
## plan
1. backdoor must disguise itself
2. backdoor must sniff all packets 
3. backdoor must authenticate messages
4. backdoor must interpret commands
5. backdoor must send results of commands
6. client must send commands
7. client must receive respose
8. messages must be encrypted
8a. server must encrypt messages
8b. server must decrypt authentic messages
8c. client must encrypt messages
8d. client must decrypt messages

## results

## captures

# misc
## header
/*
  Source:
  Functions:
  Date:
  Revivions: 
  Designers:
  Programmer: John Warren
  Usage:
  Notes:
*/