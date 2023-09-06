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
    def __init__(self,name,age,salary,level):
        super().__init__(name,age,salary)
        self.level = level
    
    # overriding methods
    def work(self):
        print (f"{self.name} is coding")


    def debug(self):
        print (f"{self.name} is debugging")
# The SoftwareEngineer class is a child class of Employee.
# It inherits the attributes and methods from the Employee class. 
# It has its own __init__ method, which extends the initialization process by calling the parent class's __init__ method using super(). 
# Additionally, it defines its own work and debug methods, which override the work method inherited from Employee.


# child class/subclass
class Designer(Employee):
  
  # overriding methods
    def work(self):
        print (f"{self.name} is designing")

    def draw(self):
        print (f"{self.name} is drawing")
# The Designer class is another child class of Employee. 
# It also inherits attributes and methods from Employee. 
# It overrides the work method inherited from Employee and defines its own draw method.

se1 = SoftwareEngineer("Kallany", 29, 60000, "Junior")
print(se1.name)
se1.work()
print(se1.level)
se1.debug()

d1 = Designer("Asma", 30, 60000)
print(d1.name)
d1.work()
d1.draw()


# This code demonstrates the concept of inheritance in Python. 
# The child classes SoftwareEngineer and Designer inherit attributes and methods from the Employee class. 
# They can extend the functionality by adding their own methods and attributes and override methods inherited from the base class.


