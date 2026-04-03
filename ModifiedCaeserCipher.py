def variable_key_caesar(text, key, mode='encrypt'):
    result = ""
    lower_table = "abcdefghijklmnopqrstuvwxyz"
    upper_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"

    for char in text:
        if char in lower_table:
            p = lower_table.index(char)
            if mode == 'encrypt':
                # Even index adds the key, Odd index subtracts it
                new_index = (p + key) if p % 2 == 0 else (p - key)
            else:
                # To decrypt, we reverse the logic based on the original parity
                # We calculate the original index by checking both possibilities.
                if (p - key) % 2 == 0:
                    new_index = (p - key)
                else:
                    new_index = (p + key)
            result += lower_table[new_index % 26]

        elif char in upper_table:
            p = upper_table.index(char)
            if mode == 'encrypt':
                # Even index adds the key, Odd index subtracts it
                new_index = (p + key) if p % 2 == 0 else (p - key)
            else:
                # To decrypt, we reverse the logic based on the original parity
                if (p - key) % 2 == 0:
                    new_index = (p - key)
                else:
                    new_index = (p + key)
            result += upper_table[new_index % 26]

        elif char in numbers:
            p = int(char)
            if mode == 'encrypt':
                # Even index adds the key, Odd index subtracts it
                new_val = (p + key) if p % 2 == 0 else (p - key)
            else:
                # To decrypt, we reverse the logic based on the original parity
                if (p - key) % 2 == 0:
                    new_val = (p - key)
                else:
                    new_val = (p + key)
            result += str(new_val % 10)
        else:
            result += char
            
    return result

# Testing with keys and
my_key = 5  # Change key to any value other than 1
secret_msg = "Hello2026"

encrypted = variable_key_caesar(secret_msg, my_key, mode='encrypt')
decrypted = variable_key_caesar(encrypted, my_key, mode='decrypt')

print(f"Key Used:  {my_key}")
print(f"Original:  {secret_msg}")
print(f"Encrypted: {encrypted}")
print(f"Decrypted: {decrypted}")