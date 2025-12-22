import random as r

def check_strength(password):
    """
    Checks the strength of a given password.
    Returns a string such as 'Weak', 'Fine', 'Good', 'Strong', or 'Invalid'.
    """
    if len(password) < 8:
        return "Invalid: Password must be at least 8 characters long."

    u = l = d = s = el = 0

    for i in password:
        if i.isupper():
            u += 1
        elif i.islower():
            l += 1
        elif i.isdigit():
            d += 1
        elif i in "@#$%^&*!":
            s += 1
        else:
            el += 1

    if el != 0:
        return "Invalid: Password contains invalid characters."
    elif u == 0:
        return "Weak: Must contain at least one uppercase letter."
    elif l == 0:
        return "Weak: Must contain at least one lowercase letter."
    elif d == 0:
        return "Fine: Must contain at least one digit."
    elif s == 0:
        return "Good: Must contain at least one special character."
    else:
        return "Strong"

def generate_password(strength="strong"):
    """
    Generates a random password of the given strength.
    """
    u_chars = [chr(65 + i) for i in range(26)]
    l_chars = [chr(97 + i) for i in range(26)]
    s_chars = ['@', '#', '$', '%', '^', '&', '*', '!']
    n_chars = [str(i) for i in range(10)]

    res = ""

    if strength == "weak":
        for _ in range(8):
            res += r.choice(l_chars)
    elif strength == "fine":
        for _ in range(4):
            res += r.choice(u_chars) + r.choice(l_chars)
    elif strength == "good":
        for _ in range(4):
            res += r.choice(u_chars) + r.choice(l_chars)
        res += r.choice(n_chars)
    elif strength == "strong":
        for _ in range(4):
            res += r.choice(u_chars) + r.choice(l_chars)
        res += r.choice(s_chars) + r.choice(n_chars)

    return res
