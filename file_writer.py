import json

""" File class """
class File:
    def __init__(self):
        self.file_name = input("Enter file name: ")
        self.file = None
    
    """ it opens the file and calls the write data function """
    def openFile(self):
        self.file = open(self.file_name, 'a')
        directory = self.writeData()
        directorys = json.dumps(directory)
        self.file.write(directorys)
        self.file.write("\n")

    """ ask the information of a user and then writting in in a dictionary format in the file """
    def writeData(self):
        username = input("Enter username: ")
        password = input("Enter password: ")
        port = str(input("Enter port number: "))
        ip = input("Enter ip: ")
        directory = {'username': username, 'password': password, 'port': port, 'ip':ip}
        return directory

    """ close the file """
    def closeFile(self):
        self.file.close()

    """ loading the directories from the file in a list """
    def loadDirectories(self):
        f = open(self.file_name, 'r')
        directories = []
        for line in f:
            directory = json.loads(line)
            directories.append(directory)
        return directories


if __name__ == "__main__":
    file = File()
    while True:
        answer = input(f"would you like to add a directory to the file? y/n: ")
        if answer == 'y':
            file.openFile()
        elif answer == 'n':
            file.closeFile()
            break
        else:
            print("Wrong answer!")
    print(f"Data Loaded to the file {file.file_name}")
    directories = file.loadDirectories()
    print(directories)