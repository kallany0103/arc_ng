# Base class/Parent class/Superclass. 
#We can inherit, extend and override this properties
class Employee:
     def __init__(self,name,age,salary):
        self.name = name
        self.age = age
        self.salary = salary

     def work(self):
        print (f"{self.name} is working")

# child class/subclass
class SoftwareEngineer(Employee):
    pass

# child class/subclass
class Designer(Employee):
    pass

se1 = SoftwareEngineer("Kallany", 29, 60000)
print(se1.name)
se1.work()

d1 = Designer("Asma", 30, 60000)
print(d1.name)
d1.work()

# This code demonstrates inheritance in Python, where the child classes SoftwareEngineer 
# and Designer inherit attributes and methods from the parent class Employee. 
# Instances of the child classes have access to the inherited attributes, such as name and age.







