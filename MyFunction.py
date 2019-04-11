import random
import string

class MyUtils:
    def CheckThaiPersonID(self, number):
        pid = str(number)
        if(len(pid) != 13):
            return False
        num = 0
        num2 = 13
        listdata = list(pid)
        # print(listdata)
        
        sum = 0
        while num < 12:
            sum += int(listdata[num])*(num2 - num)
            num += 1
        
        digit = sum % 11
        # print(digit)
        
        if digit == 0:
            digit = 1
        elif digit == 1:
            digit = 0
        else:
            digit = 11 - digit
        
        if digit == int(listdata[12]):
            return True
        else:
            return False
    
    def randomStringDigits(self, stringLength=6):
        lettersAndDigits = string.ascii_letters + string.digits
        return ''.join(random.choice(lettersAndDigits) for i in range(stringLength))

