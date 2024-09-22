import secrets
import miller_rabin
import egcd


def check_prime(candidate, iterations=40):
    return miller_rabin.miller_rabin(candidate, iterations)


def get_random_bits(bit_size):
    return secrets.randbits(bit_size)


def find_large_prime(bit_size=1024, max_attempts=10000):
    for _ in range(max_attempts):
        prime_candidate = get_random_bits(bit_size)
        if check_prime(prime_candidate):
            return prime_candidate

    raise Exception(f"Could not find a prime of size {bit_size} in {max_attempts} attempts.")


def create_prime_pair(bits=1024, delta_bits=256, max_attempts=10000):
    while True:
        prime1 = find_large_prime(bits, max_attempts)
        prime2 = find_large_prime(bits, max_attempts)
        if abs(prime1 - prime2).bit_length() >= delta_bits:
            return prime1, prime2
    raise Exception(f"Failed to generate primes within {max_attempts} attempts.")


def find_public_key_exponent(prime1, prime2, max_attempts=1000):
    totient = (prime1 - 1) * (prime2 - 1)

    for _ in range(max_attempts):
        e_candidate = get_random_bits(totient.bit_length())

        if e_candidate <= 1 or e_candidate >= totient:
            continue

        gcd, _, _ = egcd.egcd(e_candidate, totient)
        if gcd == 1:
            return e_candidate

    raise Exception(f"Failed to generate public exponent for primes {prime1} and {prime2} after {max_attempts} tries.")


def calculate_private_key(e_value, prime1, prime2):
    totient_value = (prime1 - 1) * (prime2 - 1)
    gcd, private_key, _ = egcd.egcd(e_value, totient_value)
    assert(abs(gcd) == 1)

    if private_key < 0:
        return private_key + totient_value
    return private_key


def power_mod(base, exponent, mod):
    if exponent == 0:
        return 1
    elif exponent % 2 == 1:
        return base * power_mod(base, exponent - 1, mod) % mod
    else:
        half_result = power_mod(base, exponent // 2, mod)
        return half_result * half_result % mod


def encrypt_message(plain_text, public_key, modulus):
    return power_mod(plain_text, public_key, modulus)


def decrypt_message(cipher_text, private_key, modulus):
    return power_mod(cipher_text, private_key, modulus)


prime1, prime2 = create_prime_pair(bits=128, delta_bits=32)
modulus = prime1 * prime2
public_key = find_public_key_exponent(prime1, prime2)
private_key = calculate_private_key(public_key, prime1, prime2)

print("Prime1: ", prime1)
print("Prime2: ", prime2)
print("Modulus: ", modulus)
print("Public Key: ", public_key)
print("Private Key: ", private_key)

sample_message = 1234567890
encrypted_msg = encrypt_message(sample_message, public_key, modulus)
decrypted_msg = decrypt_message(encrypted_msg, private_key, modulus)

print(f"Original Message: {sample_message}")
print(f"Encrypted Message: {encrypted_msg}")
print(f"Decrypted Message: {decrypted_msg}")

assert(sample_message == decrypted_msg)
