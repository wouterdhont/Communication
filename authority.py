from logic_authority import *
import os

os.system('cls' if os.name == 'nt' else 'clear')
print("Welcome to the authority dashboard!")
authority_id = int(input("Enter your ID: "))

print("Welcome Authority, what do you want to do?")
print("Some actions you can perform: ")
print("(1) Revoke a license")
print("(2) Reinstate a license")
print("(3) View a license status")
print("(0) Exit")



while True:
    try:
        choice = int(input("\nEnter the number of the action you want to perform: "))
    except ValueError:
        print("Invalid input. Please enter a number.")
        continue 

    match choice:
        case 1:
            user_id = int(input("Enter user_id: "))
            revoke_license(authority_id, user_id)
        case 2:
            user_id = int(input("Enter user_id: "))
            reinstate_license(authority_id, user_id)
        case 3:
            user_id = int(input("Enter user_id: "))
            view_license_status(authority_id, user_id)
        case 0: 
            print("Exiting admin panel. Goodbye!")
            break
        case _:
            print("Invalid choice. Please select a valid option.")