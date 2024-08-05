# Web Vulnerability Scanner

A Ruby-based web vulnerability scanner that checks for common vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and directory bruteforcing. This tool is designed for educational purposes only and should be used responsibly with permission from the target website's owner.

![image](https://github.com/user-attachments/assets/5a538e2b-1224-458b-a250-74a0d2246e13)


## Disclaimer

**DISCLAIMER:** This tool is for educational purposes only. The author is not liable for any illegal activities. Ensure you have permission to test the target website.

## Features

- SQL Injection vulnerability detection
- Cross-Site Scripting (XSS) vulnerability detection
- Cross-Site Request Forgery (CSRF) vulnerability detection
- Directory bruteforcing to find accessible directories and files

## Requirements

- Ruby (version 2.6 or higher)
- Nokogiri gem

## Installation

1. Ensure Ruby is installed on your system:
    ```sh
    ruby -v
    ```

2. Install the required gem:
    ```sh
    sudo gem install nokogiri
    ```

3. Clone this repository:
    ```sh
    git clone https://github.com/yourusername/web-vulnerability-scanner.git
    cd web-vulnerability-scanner
    ```

4. Ensure `payloads.txt` and `bruteforce_wordlist.txt` are in the same directory as `webvulnscan.rb`.

## Usage

1. Run the script:
    ```sh
    ruby webvulnscan.rb
    ```

2. Enter the target domain when prompted (e.g., `example.com`).
![webscan](https://github.com/user-attachments/assets/4a0e7d49-163b-4a56-938f-322b56e2de5b)

## Output

- The script will display a disclaimer.
- It will then prompt you for a target domain.
- The script will validate the URL and perform vulnerability scans using the payloads and wordlist provided.
- It will output whether it found possible vulnerabilities for SQL Injection, XSS, CSRF, and accessible directories or files.
- Detailed information on how to fix the vulnerabilities will be provided, including which payload was successfully injected.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
