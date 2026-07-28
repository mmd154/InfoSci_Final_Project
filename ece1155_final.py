"""
create test accounts with various weak passwords
hacker hashes all top 100 most commonly used passwords and compares
them to passwords stored in data base if match found hacker is able
to login with unlimited attempts with the users credentials
time will be measured from when the attacker begins to when they
can login with credentials
"""

import hashlib
import time
import random
import matplotlib.pyplot as plt

"""
list 100 most commonly used passwords
attacker tries each during attack
"""
TOP_100_PASSWORDS = [
    "123456", "123456789", "12345678", "password", "qwerty123", "qwerty1",
    "111111", "12345", "secret", "123123", "1234567890", "1234567",
    "000000", "qwerty", "abc123", "password1", "iloveyou", "11111111",
    "dragon", "monkey", "123123123", "123321", "qwertyuiop", "00000000",
    "Password", "654321", "target123", "tinkle", "zag12wsx", "1g2w3e4r",
    "gwerty123", "gwerty", "666666", "1q2w3e4r5t", "Qwerty123",
    "987654321", "1q2w3e4r", "1a123456", "1qaz2wsx", "121212", "abcd1234",
    "asdfghjkl", "88888888", "Qwerty123!", "Qwerty1!", "112233",
    "q1w2e3r4t5y6", "football", "zxcvbnm", "princess", "Qwerty1",
    "aaaaaa", "Abcd1234", "Password1", "sunshine", "147258369",
    "Qwerty1234", "Qwerty12", "123qwe", "computer", "baseball",
    "159753", "superman", "azerty", "pokemon", "michael",
    "1234qwer", "1234561", "888888", "daniel",
    "123456789a", "123654", "P@ssword", "qwer1234", "admin",
    "testing", "asdf1234", "555555", "12341234"
]

"""
counter measure constraints
"""
max_attempts = 5  #max attempts before account is locked
lockout_time = 30  #time in seconds before account is open again
login_delay = 0.1  #seconds between login attempts


"""
create a user database
98 users were given weak passwords from the 100 list
2 users were given strong passwords that are not in list
"""

def build_victim_database(num_accounts=100, num_from_dictionary=98):
    usernames = [f"user{i}" for i in range(1, num_accounts + 1)]  #generate usernames
    random.shuffle(usernames)  #shuffle weak accounts so they are random

    dictionary_users = usernames[:num_from_dictionary]  #where all users receive weak passwords
    other_users = usernames[num_from_dictionary:]  #the 2 remaining users receive strong passwords

    plaintexts = {}

    #give weak users random password from 100 list
    for username in dictionary_users:
        plaintexts[username] = random.choice(TOP_100_PASSWORDS)

    #give strong users a strong password that is not in the list
    for username in other_users:
        plaintexts[username] = "StrongPassword!" + str(random.randint(10000, 99999))

    return plaintexts

"""
create victim database
"""

plaintexts = build_victim_database()  #create users and assign passwords

#hash all passwords in database using SHA256
hashed_database = {
    username: hashlib.sha256(password.encode()).hexdigest()
    for username, password in plaintexts.items()
}


"""
countermeasure function
"""

def onlinebruteforce_lockout(plaintexts):
    #simulate online brute force attack - locks account after too many failed attempts
    start = time.perf_counter()  #time when attack begins

    cracked = {}
    failedattempts = {username: 0 for username in plaintexts}  #track failed attempts for each user
    lockeduntil = {username: 0 for username in plaintexts}  #track when each user is unlocked

    firstlog = None  #first successful login time

    #trying each password
    for password in TOP_100_PASSWORDS:
        for username, realpass in plaintexts.items():
            if username in cracked:
                continue  #skip already cracked accounts

            current = time.perf_counter()  #current time

            if current < lockeduntil[username]:  #skip locked accounts
                continue
            time.sleep(login_delay)  #simulate delay between login attempts
            if password == realpass:  #if correct password
                cracked[username] = password
                if firstlog is None:
                    firstlog = time.perf_counter() - start
            else:
                failedattempts[username] += 1  #increment failed attempts
                if failedattempts[username] >= max_attempts:  #lock account if too many failed attempts
                    lockeduntil[username] = (time.perf_counter() + lockout_time)
                    failedattempts[username] = 0  #reset failed attempts after lockout

    totaltime = time.perf_counter() - start  #stop timing once every password has been tried

    return firstlog, totaltime, len(cracked)


"""
starting the attack
"""

start = time.perf_counter()  #time when attack begins

cracked = {}  #storing cracked accounts and their passwords
cracked_time = {}  #storing time taken to crack each account
first_login = None  #first successful login time

#try each password in dictionary
for password in TOP_100_PASSWORDS:
    candidate_hash = hashlib.sha256(password.encode()).hexdigest()  #hash password

    for username, stored_hash in hashed_database.items():  #compare against every stored password hash
        if username in cracked:  #skip already cracked accounts
            continue

        if candidate_hash == stored_hash:  #if match, found password
            cracked[username] = password
            cracked_time[username] = time.perf_counter() - start

            if first_login is None:  #record login
                first_login = cracked_time[username]

time_taken = time.perf_counter() - start  #stop timing once every password has been tried


"""
print section to display results of attack
"""

print(f"Victim database contained {len(plaintexts)} accounts.\n")

for username in hashed_database:  #print if each account was cracked or not
    if username in cracked:
        status = f"Cracked: {cracked[username]} at {cracked_time[username] * 1000:.4f} ms"
    else:
        status = "Not cracked"

    print(f"{username}: {status}")

print(f"\n{len(cracked)}/{len(hashed_database)} accounts hacked")  #print status

if first_login is not None:  #print time attacker can login
    print(f"Time until attacker can login with valid credentials: {first_login * 1000:.4f} ms")
else:
    print("Attacker did not find any accounts.")

print(f"Total time taken for attack: {time_taken:.6f} seconds")  #print total attack time

"""
run countermeasure
"""
print("\n------------------------------------------\n")
print("\nRunning countermeasure simulation...\n")
print("\n------------------------------------------\n")

lockout_f, lockout_t, lockout_c = onlinebruteforce_lockout(plaintexts)  #lockout first time, lockout total amount, lockout cracked amount

print(f"Accounts hacked: {lockout_c}/100")
print(f"Time to first login: {lockout_f:.4f} seconds")
print(f"Total attack time: {lockout_t:.4f} seconds")


"""
graph of attack vs countermeasure
"""

label = ['No Countermeasure', 'Countermeasure']

timedata = [time_taken, lockout_t]  #time taken for each attack

plt.figure(figsize=(6, 4))

plt.bar(label, timedata, color=['red', 'green'])
plt.ylabel('Time (seconds)')
plt.title('Attack Time Comparison: No Countermeasure vs Countermeasure')

for i, t in enumerate(timedata):
    plt.text(i, t, f"{t:.6f}s", ha='center', va='bottom')

plt.tight_layout()
plt.show()