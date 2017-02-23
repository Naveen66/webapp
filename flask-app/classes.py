class test:

    count = 0

    def __init__(self):
        pass

    def user_inputs(self, count):

        name = input("Enter Name :")
        salary = input("Enter Salary : ")
        age = input("Enter Age : ")
        if count == 1:
            print name, salary, age

test()
