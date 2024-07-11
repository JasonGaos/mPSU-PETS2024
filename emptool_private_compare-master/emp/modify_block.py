import os
import re
def replace_text_in_file(file_path, old_text, new_text):
    with open(file_path, 'r') as file:
        filedata = file.read()

    pattern = re.compile(r'(?<![\w_])block(?![\w_\.])')
    if pattern.search(filedata):
        newdata = pattern.sub(new_text, filedata)
        with open(file_path, 'w') as file:
            file.write(newdata)
        return True
    return False

def replace_text_in_directory(directory, old_text, new_text):
    for subdir, _, files in os.walk(directory):
        for file in files:
            if file.split(".")[-1] not in ['cpp','hpp','h']:
                continue
            file_path = os.path.join(subdir, file)
            if replace_text_in_file(file_path, old_text, new_text):
                print(f"Replaced text in: {file_path}")

if __name__ == "__main__":
    directory = input("Enter the directory path: ")
    replace_text_in_directory(directory, r'\bblock\b', 'empBlock')

