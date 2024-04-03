
# HashCheck

HashCheck is a Python application designed to compute and verify hash values of files using various hash algorithms. It provides a simple GUI interface for users to select files, choose hash algorithms, and compare hash values.

![image](https://github.com/pyroalww/HashCheck/assets/134533935/abec9a20-e650-4d3e-a5e9-301a223ceaf1)

## Usage

1. **Installation**:
   - Ensure you have Python installed on your system.
   - Install the required dependencies using pip:
     ```
     pip install pyperclip
     pip install hashlib
     pip install tk
     pip install ttkthemes
     ```

2. **Clone the Repository**:
   ```
   git clone https://github.com/pyroalww/HashCheck.git
   ```

3. **Run the Application**:
   ```
   python main.py
   ```

4. **Using the Application**:
   - Upon launching the application, you will be presented with a GUI interface.
   - Click on the "Browse" button to select a file.
   - Choose the desired hash algorithms.
   - Enter the hash value to check against the file's hash.
   - Click on the "Check" button to compare hash values.
   - The result will be displayed indicating whether the hashes match or not.

## Features

- Supports multiple hash algorithms including MD5, SHA-1, and SHA-256.
- Displays real-time hash comparison results.
- Ability to copy computed hashes to the clipboard.

## Contributors

- [@pyroalww](https://github.com/pyroalww)
- [@c4gwn](https://instagram.com/c4gwn)

## License

This project is licensed under the terms of the MIT License.
