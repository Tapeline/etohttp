import random
from Crypto.Util import number # pip install pycryptodome

print("Generating 1024-bit RSA keys... wait...")
bits = 1024
p = number.getPrime(bits // 2)
q = number.getPrime(bits // 2)
n = p * q
e = 65537
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print(f"\nSERVER_N = {n}")
print(f"SERVER_D = {d}")
print(f"\nCLIENT_N_STR = \"{n}\"")
print(f"CLIENT_E_STR = \"{e}\"")
