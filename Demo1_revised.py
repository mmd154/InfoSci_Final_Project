"""

System Model:
    A simplified password-based authentication system that stores
    credentials as cryptographic hashes in a "database" (a Python dict).

Attack Model:
    Offline Dictionary Attack - the attacker has stolen the hash database
    and checks it against a list of the top 100 most common passwords.
    The attacker does not interact with the live login system at all.

Countermeasure:
    Comparing a fast, unsalted hash (SHA-256) against a slow, salted,
    cost-tunable hash (bcrypt) to show the measurable impact of hash
    algorithm choice on attack feasibility.
"""

import hashlib
import time
import random
import bcrypt

# ---------------------------------------------------------------------------
# Attacker's dictionary: top 100 most common passwords
# ---------------------------------------------------------------------------
TOP_100_PASSWORDS = [
    "123456", "123456789", "12345678", "password", "qwerty123", "qwerty1",
    "111111", "12345", "secret", "123123", "1234567890", "1234567",
    "000000", "qwerty", "abc123", "password1", "iloveyou", "11111111",
    "dragon", "monkey", "123123123", "123321", "qwertyuiop", "00000000",
    "Password", "644321", "target123", "tinkle", "zag12wsx", "1g2w3e4r",
    "gwerty123", "gwerty", "666666", "1q2w3e4r5t", "Qwerty123", "987654321",
    "1q2w3e4r", "a123456", "1qaz2wsx", "121212", "abcd1234", "asdfghjkl",
    "123456a", "88888888", "Qwerty123!", "Qwerty1!", "112233",
    "q1w2e3r4t5y6", "football", "zxcvbnm", "princess", "Qwerty1",
    "aaaaaa", "Abcd1234", "Password1", "sunshine", "147258369",
    "Qwerty1234", "fuckyou", "Qwerty12", "123qwe", "computer", "baseball",
    "159753", "superman", "azerty", "dearbook", "pokemon", "michael",
    "1234qwer", "1234561", "888888", "daniel", "111222tianya",
    "1qaz2wsx3edc", "123456789a", "123654", "P@ssword", "qwer1234",
    "Qwerty1?", "789456123", "Qwerty123?", "q1w2e3r4",
    "shadow", "222222", "soccer", "qwe123", "7777777", "22535", "asdasd",
    "admin", "killer", "testing", "qazwsx", "asdf1234", "1314520",
    "555555", "12341234",
]

# Uncommon/strong passwords 
STRONG_PASSWORDS = [
    "Xk9#mQ2vL7pR",
    "correcthorsebatterystaple99!",
    "Tr0ub4dor&3xyz",
    "Zq8$wNf4Yc2m",
]

# Parameters
# ---------------------------------------------------------------------------
NUM_ACCOUNTS = 10          # total accounts in the victim database
NUM_WEAK_ACCOUNTS = 2     # how many accounts get a top-100 password
BCRYPT_COST = 12          # bcrypt work factor (higher = slower/stronger)


# Build a randomized victim database
# ---------------------------------------------------------------------------
def build_victim_database(num_accounts, num_weak):
    """
    Randomly assigns `num_weak` accounts a common (crackable) password and 
    the rest of the accounts (sum_accounts - num_weak) a strong (uncrackable) password.
    """
    usernames = [f"user{i}" for i in range(1, num_accounts + 1)]
    random.shuffle(usernames)

    weak_users = usernames[:num_weak]
    strong_users = usernames[num_weak:]

    plaintexts = {}
    for u in weak_users:
        plaintexts[u] = random.choice(TOP_100_PASSWORDS)
    for u in strong_users:
        plaintexts[u] = random.choice(STRONG_PASSWORDS)
    return plaintexts


# Hashing functions
# ---------------------------------------------------------------------------
def hash_sha256(password):
    """Unsalted SHA-256 hash"""
    return hashlib.sha256(password.encode()).hexdigest()


def check_sha256(password, stored_hash):
    return hash_sha256(password) == stored_hash


def hash_bcrypt(password, cost=BCRYPT_COST):
    """Salted bcrypt hash"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost))


def check_bcrypt(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash)


# Offline dictionary attack
# ---------------------------------------------------------------------------
def run_dictionary_attack(hashed_db, check_fn):
    """
    Attempts to crack every account in hashed_db using TOP_100_PASSWORDS.
    Returns (cracked_dict, elapsed_seconds).
    """
    start = time.perf_counter()
    cracked = {}
    for username, stored_hash in hashed_db.items():
        for candidate in TOP_100_PASSWORDS:
            if check_fn(candidate, stored_hash):
                cracked[username] = candidate
                break
    elapsed = time.perf_counter() - start
    return cracked, elapsed


def print_results(label, hashed_db, cracked, elapsed):
    print(f"\n--- {label} ---")
    for username in hashed_db:
        status = f"CRACKED -> {cracked[username]}" if username in cracked else "not cracked"
        print(f"  {username}: {status}")
    print(f"  {len(cracked)}/{len(hashed_db)} accounts compromised")
    print(f"  Time: {elapsed:.6f} seconds")


# Main: run attack BEFORE and AFTER the countermeasure
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Build one victim database 
    plaintexts = build_victim_database(NUM_ACCOUNTS, NUM_WEAK_ACCOUNTS)

    # Before countermeasure (unsalted SHA-256)
    sha256_db = {u: hash_sha256(pw) for u, pw in plaintexts.items()}
    cracked_sha, time_sha = run_dictionary_attack(sha256_db, check_sha256)
    print_results("BEFORE countermeasure (SHA-256, unsalted)",
                   sha256_db, cracked_sha, time_sha)

    # After countermeasure (salted bcrypt)
    bcrypt_db = {u: hash_bcrypt(pw) for u, pw in plaintexts.items()}
    cracked_bc, time_bc = run_dictionary_attack(bcrypt_db, check_bcrypt)
    print_results("AFTER countermeasure (bcrypt, salted)",
                   bcrypt_db, cracked_bc, time_bc)

    # Summary comparison
    print("\n--- Countermeasure Impact Summary ---")
    print(f"  SHA-256 crack time:  {time_sha:.6f} s")
    print(f"  bcrypt  crack time:  {time_bc:.6f} s")
    if time_sha > 0:
        print(f"  Slowdown factor:     {time_bc / time_sha:.1f}x")