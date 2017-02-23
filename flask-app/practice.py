#!/usr/bin/python


class Employee():
    """"Common base class for all employees"""
    empCount = 0

    def __init__(self, name, salary, age):
        self.name = name
        self.salary = salary
        self.age = age
        # Employee.empCount += 1

    def displayCount(self):
        print "Total Employee %d" % Employee.empCount

    def displayEmployee(self):
        print "Name : ", self.name, ", Salary: ", self.salary, ", age: ", self.age

    def user_inputs(self):
        count = input("Enter employee count :")
        name = input("Enter Name :")
        salary = input("Enter Salary : ")
        age = input("Enter Age : ")
        for i in count:
            if i == Employee.empCount:


"This would create first object of Employee class"
emp1 = Employee("Zara", 2000, 20)
"This would create second object of Employee class"
emp2 = Employee("Manni", 5000, 30)
emp1.displayEmployee()
emp2.displayEmployee()
print "Total Employee %d" % Employee.empCount

