def triangle(base, height):
    #area = 0.05 * base * height
    area = 0.05 * int(base) * int(height)
    return area

def calculating_minutes(day):
    result = day*24*60
    return result

def is_prime(num):
    if num > 1:
        for i in range(2, num):
            if (num % i) == 0:
                return False
            else:
                return True
    else:
        return False
