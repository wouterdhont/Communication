from logic_admin import *
import os

os.system('cls' if os.name == 'nt' else 'clear')
print("Welcome to the admin dashboard!")
admin_id = int(input("Enter your ID: "))
print("\nWhat do you want to do?")
print("Some actions you can perform: ")
print("(1) View logs")
print("(2) Create a user")
print("(3) Delete a user")
print("(4) Assign a role")
print("(5) View all users")
print("(0) Exit")

while True:
    try:
        choice = int(input("\nEnter the number of the action you want to perform: "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        continue

    match choice:
        case 1:
            key = input("Enter the key: ")
            day = input("Enter the day: ")
            view_logs(admin_id, key, day)
        case 2:
            name = input("Enter a name: ")
            age = int(input("Enter an age: "))
            user_id = int(input("Enter a user_id: "))
            user_data = {
                "name": name,
                "age": age,
                "user_id": user_id,
                "role": "user",
                "totp_secret": "new totp",
                "has_drivers_license": True,
                "able_to_drive": True
            }
            create_user(admin_id, user_data)
        case 3:
            user_id = int(input("Enter user_id: "))
            delete_user(admin_id, user_id)
        case 4:
            user_id = int(input("Enter a user_id: "))
            role = input("Enter a role: ")
            assign_role(admin_id, user_id, role)
        case 5:
            view_all_users(admin_id)
        case 0:
            print("Exiting admin panel. Goodbye!")
            break
        case _:
            print("Invalid choice. Please select a valid option.")