class Employee:
    def __init__(self, name, age):
        self._name = name  # Protected attribute
        self._age = age  # Protected attribute
        self.__salary = None  # Private attribute

    def work(self):
        print(f"{self._name} is working")

    def get_salary(self):
        return self.__salary

    def set_salary(self, new_salary):
        self.__salary = new_salary


class SoftwareEngineer(Employee):
    def __init__(self, name, age, salary, level):
        super().__init__(name, age)
        self._level = level  # Protected attribute
        self.set_salary(salary)

    def work(self):
        print(f"{self._name} is coding")

    def debug(self):
        print(f"{self._name} is debugging")


class Designer(Employee):
    def work(self):
        print(f"{self._name} is designing")

    def draw(self):
        print(f"{self._name} is drawing")


se1 = SoftwareEngineer("Kallany", 29, 60000, "Junior")
print(se1._name)  # Output: Kallany (Accessing protected attribute)
se1.work()
print(se1._level)  # Output: Junior (Accessing protected attribute)
se1.debug()
#print(se1.__salary)  # Error: AttributeError - 'SoftwareEngineer' object has no attribute '__salary'
print(se1.get_salary())  # Output: 60000 (Accessing private attribute using a getter method)

se1.set_salary(65000)  # Updating the salary using the setter method
print(se1.get_salary())  # Output: 65000 (Accessing the updated salary)

d1 = Designer("Asma", 30)
print(d1._name)  # Output: Asma (Accessing protected attribute)
d1.set_salary(70000)
print(d1.get_salary())
