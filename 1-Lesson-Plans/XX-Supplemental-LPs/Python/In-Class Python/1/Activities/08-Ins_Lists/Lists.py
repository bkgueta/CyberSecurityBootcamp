# Create a list and save it to a variable
hobbies = ["Rock Climbing", "Bug Collecting", "Cooking", "Knitting", "Writing"]
print(hobbies)

# Select the first and second values from the list
print(hobbies[0])
print(hobbies[1])

print("hobby at index 4: ")
print(hobbies[4])

# len() tells us how long the list is (5)
print("length of hobbies list: ")
print(len(hobbies))

# Use index() to find the index of a specific value in a list
print("index of cooking in list: ")
print(hobbies.index("Cooking"))

# Use append() to add values to the end of the list
hobbies.append("Gaming")
print(hobbies)

# Use remove() to remove values from the list
hobbies.remove("Bug Collecting")
print(hobbies)

