from faker import Faker
import sys
import time
from random import randint

from splinter import Browser


def main():

    print("Generating " + sys.argv[1] +" users for checkzilla.io...")
    print("Output in checkzillaUsers.txt")

    checkzillaUsers = open(r"checkzillaUsers.txt","a+")
    browser = Browser()
    fake = Faker()
    userNameList = []

    currentUsers = checkzillaUsers.read()


    for i in range(int(sys.argv[1])): 
        username = fake.user_name().zfill(6)
       
        if (username not in userNameList) and (username not in currentUsers):
                
            userNameList.append(username)
            password = fake.password(length=10,special_chars=True, digits=True, upper_case=True, lower_case=True)
                        
            print(username + "  |  " + password)

            browser.visit("http://checkzilla.io")

            browser.click_link_by_href('#popup1')

            browser.fill("reguser",username)
            browser.fill("regpass",password)
            browser.fill("pass-confirm",password)
            browser.find_by_css('.text1').first.click()
            
            browser.find_by_css('.s-popup-btn').first.click()

            
            browser.cookies.delete()

            checkzillaUsers.write(username + "  |  " + password +"\n")

            browser.reload()
    
    checkzillaUsers.close()
    browser.quit()
            


if __name__ == "__main__":
    main()