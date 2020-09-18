def ascii_encrypt(string):
    symbols = list(string)
    encrypted_string = ''
    for symbol in symbols:
        encrypted_string += '{0}*'.format(encryption_function(symbol))
    return encrypted_string[:-1]


def ascii_decrypt(encrypted_string):
    numbers = []
    stringed_numbers = encrypted_string.split('*')
    for stringed_number in stringed_numbers:
        numbers.append(float(stringed_number))
    decrypted_string = ''
    for number in numbers:
        decrypted_string += decryption_function(number)
    return decrypted_string


def encryption_function(symbol):
    number = ord(symbol)
    number /= 10
    return number


def decryption_function(number):
    number *= 10
    return chr(int(number))
