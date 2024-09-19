import requests
import hashlib


def request_api_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'error fetching : {res.status_code} check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        # check if the tail of the has is equal to hash to check
        if h == hash_to_check:
            # count is the number of times the password has been leaked
            return count
    return 0
    # print(hashes)


def pwned_api_check(password):
    print(password.encode('utf-8'))
    # has password
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # grab the start-up to the 5th character, and the fifth character upto the end
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    # print(first5_char, tail)
    print(response)
    return get_password_leaks_count(response, tail)


def main():
    print("Enter passwords to check (one per line). Press Enter on an empty line to finish:")
    while True:
        password = input("Password: ").strip()
        if not password:  # Exit the loop if the input is empty
            break
        count = pwned_api_check(password)
        if count:
            print(f"'{password}' was found {count} times... You should use another one!")
        else:
            print(f"'{password}' was not found... It is safe to use!")


if __name__ == '__main__':
    main()
