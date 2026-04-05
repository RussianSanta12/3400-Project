def variable_key_caesar(text, key, mode='encrypt'):
    result = ""
    lower_table = "abcdefghijklmnopqrstuvwxyz"
    upper_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    numbers = "0123456789"

    for char in text:
        if char in lower_table:
            p = lower_table.index(char)
            if mode == 'encrypt':
                new_index = (p + key) if p % 2 == 0 else (p - key)
            else:
                if (p - key) % 2 == 0:
                    new_index = (p - key)
                else:
                    new_index = (p + key)
            result += lower_table[new_index % 26]

        elif char in upper_table:
            p = upper_table.index(char)
            if mode == 'encrypt':
                new_index = (p + key) if p % 2 == 0 else (p - key)
            else:
                if (p - key) % 2 == 0:
                    new_index = (p - key)
                else:
                    new_index = (p + key)
            result += upper_table[new_index % 26]

        elif char in numbers:
            p = int(char)
            if mode == 'encrypt':
                new_val = (p + key) if p % 2 == 0 else (p - key)
            else:
                if (p - key) % 2 == 0:
                    new_val = (p - key)
                else:
                    new_val = (p + key)
            result += str(new_val % 10)
        else:
            result += char
            
    return result

def columnar_transposition(text, key, mode='encrypt'):
    """
    Scrambles character positions by writing them into columns
    determined by the length of the key.
    """
    # Use absolute value of key to determine columns
    num_cols = max(2, abs(key) % 10) 
    
    if mode == 'encrypt':
        # Write rows, read columns
        columns = [''] * num_cols
        for i, char in enumerate(text):
            columns[i % num_cols] += char
        return "".join(columns)
    
    else:
        # Determine the length of each column to reconstruct
        num_rows = len(text) // num_cols
        extra_chars = len(text) % num_cols
        
        col_lengths = [num_rows + (1 if i < extra_chars else 0) for i in range(num_cols)]
        columns = []
        idx = 0
        for length in col_lengths:
            columns.append(text[idx:idx+length])
            idx += length
            
        # Read across the columns to rebuild the original string
        result = []
        for i in range(len(text)):
            col_idx = i % num_cols
            row_idx = i // num_cols
            result.append(columns[col_idx][row_idx])
        return "".join(result)

def secure_cipher(text, key, mode='encrypt'):
    if mode == 'encrypt':
        # Substitute (Caesar) -> Transpose (Scramble)
        substituted = variable_key_caesar(text, key, mode='encrypt')
        return columnar_transposition(substituted, key, mode='encrypt')
    else:
        # Reverse Transpose -> Reverse Substitute
        unscrambled = columnar_transposition(text, key, mode='decrypt')
        return variable_key_caesar(unscrambled, key, mode='decrypt')

# Testing
my_key = 5
secret_msg = "Benjamin Netanyahu"

encrypted = secure_cipher(secret_msg, my_key, mode='encrypt')
decrypted = secure_cipher(encrypted, my_key, mode='decrypt')

print(f"Key Used:   {my_key}")
print(f"Original:   {secret_msg}")
print(f"Encrypted:  {encrypted}")
print(f"Decrypted:  {decrypted}")