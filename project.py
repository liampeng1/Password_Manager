import string
import random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC
from Crypto import Random
from Crypto.Util.strxor import strxor

# secure password management application

# user creates master password

# users securely add passwords using:
# • username for the account
# • associated URL
# • master password

# users retrieve password by entering:
# • username for the account
# • associated URL
# • master password
# and the password is copied to the clipboard

appdata = b'\x00'
mac_length = 32
masterPwd = b'\x00'

def start():
    global appdata
    global masterPwd

    print ("Welcome to PassFast!")

    if get_appdata():
        userInput = input("Type your Master Password into the Terminal window and press ENTER. \nNote: if you enter your Master Password incorrectly, the application will not work as intended. \n")
        masterPwd = bytes(userInput,'utf-8')
        # if there appdata.txt exists, then the user already has masterPwd

    else:
        new_master()




def get_appdata():
    global appdata
    try:
        appdata_file = open("appdata.txt", 'rb')
        appdata = appdata_file.read()
        appdata_file.close()
        return True
    except IOError:
        return False

def new_master():
    global appdata
    global masterPwd

    print ("You don't have any data for this application saved on this system, so we'll start from scratch.")
    print ("We'll go ahead and give you a very important tring called a Master Password, which you will always need in order to use this application and access your saved passwords.")
    print ("Here it is, be sure to memorize it:")
    chars = string.ascii_letters + string.digits + "!@#$%^&*()+_"
    master = ''.join(random.choice(chars) for x in range(12))

    print('\n'+master+'\n')

    masterPwd = bytes(master,'utf-8')
    appdata_file = open("appdata.txt", "w+")
    appdata_file.close()
    appdata = Random.get_random_bytes(64)
    set_mac()
    write_appdata_to_file()
    start()

def verify_mac():
    global appdata
    global masterPwd
    print ("---------------")
    print (str(generate_mac()))
    print ("================")
    print (str(appdata[:-32]))
    print ("---------------")
    generate_mac() == appdata[:-32]

def generate_mac():
    global appdata
    global masterPwd
    # create hash of master password
    hash = SHA256.new()
    hash.update(masterPwd)
    mackey = hash.digest()
    # create mac using hash of master password as mac key for rest of file
    MAC = HMAC.new(mackey, digestmod=SHA256)
    MAC.update(appdata[:-32])
    new_mac = MAC.digest()
    return new_mac

def set_mac():
    global appdata
    global masterPwd
    new_mac = generate_mac()
    # remove old mac
    appdata = appdata[:-32]
    # add new mackey
    appdata = appdata + new_mac

def write_appdata_to_file():
    global appdata
    appdata_file = open("appdata.txt", 'wb')
    appdata_file.write(appdata)
    appdata_file.close()

def set_password():
    global appdata
    global masterPwd
    # prompt user to enter URL and username
    URL = input("Type the URL (or some other information) for the website (or service) associated with the account whose password you wish to access, and press ENTER. \nMake sure that you remember this, as you will need to enter the same thing to access your saved password information access.")
    username = input("Now type the username associated with the password you want to save, and press ENTER. \nOnce again, be sure to remember what you enter here, as you must type it in exactly to access a stored password.")
    # Compute a SHA-2 hash of the concatenated URL and username associated with that password, and search for this.
    hash = SHA256.new()
    hash.update(URL+ '|' + username)
    infoHashed = hash.digest()
    # Generate new password and copy to clipboard
    chars = string.ascii_letters + string.digits + "!@#$%^&*()+_"
    password = ''.join(random.choice(chars) for x in range(12))
    pyperclip.copy(password)
    # create salt
    salt = get_random_bytes(8)
    # Create one-time-pad using PBKDF2 (with masterPwd as password, salt as salt, dkLen as len(masterPwd), and count as 1000)
    one_time_pad = PBKDF2(masterPwd, salt, dkLen=len(masterPwd), count=1000)
    # XOR with one-time-pad to create ciphertext
    ciphertext = strxor(password, one_time_pad)
    # save \n + infoHashed +  \n + salt + \n + ciphertext + \n before mac
    appdata = appdata[:-32] + "\n" + infoHased + "\n" + salt + "\n" + ciphertext + "\n" + appdata[-32:]

    # update the mac
    set_mac()

    write_appdata_to_file()

def retrieve_password():
    global appdata
    global masterPwd
    # If the user chooses to access a previosly saved password
    URL = input("Type the URL (or some other information) for the website (or service) associated with the account whose password you wish to access, and press ENTER. \nMake sure that what you enter here is the exact same text typed in when you originally saved the password you want to access.")
    username = input("Now type the username associated with the password you want to access, and press ENTER.")
    # Compute a SHA-2 hash of the concatenated URL and username associated with that password, and search for this.
    hash = SHA256.new()
    hash.update(URL+ '|' + username)
    infoHashed = hash.digest()
    # Parse appdata.txt for infoHashed
    # save the line under infoHashed as "salt," and the line under salt as "ciphertext"
    # Create one-time-pad using PBKDF2 (with masterPwd as password, salt as salt, dkLen as len(masterPwd), and count as 1000)
    # XOR this one-time-pad with ciphertext
    pyperclip.copy(password)



    hash = SHA256.new()
    hash.update(masterPwd)
    mackey = hash.digest()
    p = PBKDF2(password, salt, dkLen=len(enc_exp_e), count=1000)

def run_application():
    global appdata
    global masterPwd
    if not verify_mac():
        print ("IT'S A TRAP!!!")
        print ("Delete your file and start over. Someone has tampered with it.")
        print ("That or you entered the wrong master password.")
        exit()
    # The user chooses whether to create a new password or access a previously saved one
    print ("Would you like to set or retrieve a password?")
    goal = input("Enter 's' to set ot 'r' to retrieve and then press ENTER.\n")
    if goal == 's':
        set_password()
    if goal == 'r':
        retrieve_password()

def main():
    global appdata
    global masterPwd
    start()
    run_application()

if __name__== "__main__":
    main()