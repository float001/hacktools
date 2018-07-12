#!/usr/bin/python
# --*-- coding:utf-8 --*--

from crypt import crypt

def testpasswd(cryptpasswd):
    salt = cryptpasswd
    print salt

    dictfile = open("dics.data","r")
    for word in dictfile.readlines():
        word = word.strip("\n")
        cryptword = crypt(word, salt)
        cryptpasswd1 = cryptpasswd.replace("\n","")
        if cryptword == cryptpasswd1:
            print 'Found Pasword!!!,密码为：' + word + "\n"
            return
    print "Password not found !! \n"
    return

def main():
    passfile = open("passwordunix")
    for line in passfile.readlines():
        print "[+] 破解密码中。。。。。。。"
        testpasswd(line)

if __name__ == "__main__":
    main()

