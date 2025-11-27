# First Part
both correct example of usage, and incorrect example of usage, i wanted to see diff on the first glance
**Output**
```
Correct encryption
Correct: Decrypted response from deadbeef: Hello deadbeef, this is a secure message!

Incorrect encryption
Incorrect: Expected failure - 400: Ciphertext with incorrect length.
```
# Second Part
## Task A
1. add two users with keys,
2. encrypt their messages with partners keys,
3. send and display received messages
4. rejoice
**Output**
```
SUCCESS: Dodano klucz dla: alice
SUCCESS: Dodano klucz dla: bob
SUCCESS: Dodano wiadomość dla: bob
User2 received: Hello from User1 to User2
SUCCESS: Dodano wiadomość dla: alice
User1 received: Hello back from User2 to User1
```
## Task B
to fullfill task, signature needed to be added
**Output**
```
SUCCESS: Dodano klucz dla: carol
SUCCESS: Dodano klucz dla: dave
SUCCESS: Dodano wiadomość dla: dave
User2 received verified message: Signed message from User1
```