from logic_car_distributor import *
import os

os.system('cls' if os.name == 'nt' else 'clear')

print("Welcome Car Distributor, what do you want to do?")
print("Some actions you can perform: ")
print("(1) register a car")
print("(2) assign ownership")
print("(3) view car inventory")
print("(4) set license plate")
car_distributor_id = int(input("Enter your id: "))




while True:
    try:
        choice = int(input("\nEnter the number of the action you want to perform: "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        continue 

    match choice:
        case 1:
            car_id = int(input("Enter a car_id: "))
            make = input("Enter the car make: ")
            model = input("Enter the car model: ")
            year = int(input("Enter the year: "))
            license_plate = input("Enter the license plate: ")
            owner_id = int(input("Enter the owner_id: "))
            car_data = {
                "id": car_id,
                "make": make,
                "model": model,
                "year": year,
                "license_plate": license_plate,
                "owner_id": owner_id,
                "locked": True
            }
            register_car(car_distributor_id, car_data)
        case 2:
            user_id = int(input("Enter user_id: "))
            car_id = int(input("Enter car_id: "))
            assign_ownership(car_distributor_id, user_id, car_id)
        case 3:
            view_car_inventory(car_distributor_id)
        case 4:
            car_id = int(input("Enter the car_id: "))
            license_plate = input("Enter the license plate: ")
            set_license_plate(car_distributor_id, car_id, license_plate)
        case 0: 
            print("Exiting admin panel. Goodbye!")
            break
        case _:
            print("Invalid choice. Please select a valid option.")