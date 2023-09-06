class SoftwareEngineer:
    def __init__(self, name, age, level, salary):
        # instance attributes
        self.name = name
        self.age = age
        self.level = level
        self.salary = salary
    # The __init__ method is a special method in Python classes that serves as the constructor for the class. 
    # It gets called automatically when creating a new instance of the class. 
    # The primary purpose of the __init__ method is to initialize the attributes of the object.

    def code(self):
        print(f"{self.name} is writing a code")

    def code_in_language(self, language):
        print(f"{self.name} is writing code in {language}")

    def information(self):
        information = f"name= {self.name}, age= {self.age}, level= {self.level}"
        return information

    def __str__(self):
        information = f"name= {self.name}, age= {self.age}, level= {self.level}"
        return information
    
    def __eq__(self,other):
        return self.name == other.name and self.age == other.age
    #The __eq__ method is a special method in Python classes that defines the behavior 
    # of the equality operator (==) when comparing objects of the class.
    # It allows us to customize how two objects are considered equal.
    # It compares the name and age attributes of two objects (self and other). 
    # It returns True if both attributes are equal and False otherwise.
    # If you don't define the __eq__ method in a class, the default equality comparison will be performed based on object identity 
    # (i.e., whether the objects refer to the same memory location).
    # By default, if you compare two instances of a class using the equality operator (==), 
    # it checks if the two objects are the same instance (i.e., they refer to the same memory location)

se1 = SoftwareEngineer('Kallany', 29, 'Junior', 60000)
se2 = SoftwareEngineer('Israt', 28, 'Senior', 80000)
se3 = SoftwareEngineer('Israt', 28, 'Senior', 80000)
print(se1.name)
print(se2.name)
print(se1.level)
print(se1.salary)


se1.code()
se2.code_in_language('Python')
print(se1.information())
print(se2)
print(se2==se3)

#The __str__ method is a special method in Python classes that defines the string representation of an object. 
# It is automatically called when we use the str() function or the print() function on an instance of the class.
#If you don't define the __str__ method in a class, the default string representation of the object will be used. 
# The default representation includes the class name and the memory address of the object.
#we want to print information of an instance(object) for example print(se2),
#Without a custom __str__ method, the output will be something like <__main__.Person object at 0x7f8c8a32d280>
#By defining the __str__ method, you can override this default behavior and provide a more useful
#and descriptive string representation of the object. 



