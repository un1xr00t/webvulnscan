require 'net/http'
require 'uri'
require 'nokogiri'

def colorize(text, color_code)
  "\e[#{color_code}m#{text}\e[0m"
end

def display_disclaimer
  puts "=========================================="
  puts colorize("DISCLAIMER: This tool is for educational purposes only.", 33)
  puts colorize("The author is not liable for any illegal activities.", 33)
  puts colorize("Ensure you have permission to test the target website.", 33)
  puts "=========================================="
  puts
end

def get_user_input
  print "Enter the target domain (e.g., example.com): "
  domain = gets.chomp
  "https://#{domain}"
end

def valid_url?(url)
  uri = URI.parse(url)
  uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
rescue URI::InvalidURIError
  false
end

def load_payloads(file_path)
  sections = {}
  current_section = nil

  File.open(file_path, "r").each_line do |line|
    line = line.strip
    next if line.empty?

    if line.start_with?("#")
      current_section = line.gsub("#", "").strip.downcase.to_sym
      sections[current_section] = []
    else
      sections[current_section] << line if current_section
    end
  end

  sections
end

def load_wordlist(file_path)
  wordlist = []
  File.open(file_path, "r").each_line do |line|
    wordlist << line.strip unless line.strip.empty?
  end
  wordlist
end

def sql_injection_check(url, param, payload)
  uri = URI.parse(url)
  params = { param => payload }
  uri.query = URI.encode_www_form(params)
  response = Net::HTTP.get_response(uri)

  if response.body.include?("syntax error") || response.body.include?("SQL")
    puts colorize("Possible SQL Injection vulnerability found.", 31)
    puts colorize("Payload: #{payload}", 31)
    puts colorize("SQL Injection vulnerabilities occur when untrusted data is included in SQL queries without proper sanitization.", 33)
    puts colorize("Fix: Use prepared statements or ORM frameworks to avoid SQL injection vulnerabilities. More info: https://owasp.org/www-community/attacks/SQL_Injection", 33)
  else
    puts "No SQL Injection vulnerability found with payload: #{payload}"
  end
rescue => e
  puts colorize("Error during SQL Injection check: #{e.message}", 31)
end

def xss_check(url, param, payload)
  uri = URI.parse(url)
  params = { param => payload }
  uri.query = URI.encode_www_form(params)
  response = Net::HTTP.get_response(uri)

  if response.body.include?(payload)
    puts colorize("Possible XSS vulnerability found.", 31)
    puts colorize("Payload: #{payload}", 31)
    puts colorize("Cross-Site Scripting (XSS) vulnerabilities occur when an attacker can inject malicious scripts into a web page viewed by other users.", 33)
    puts colorize("Fix: Ensure proper escaping of user inputs and use Content Security Policy (CSP) to mitigate XSS risks. More info: https://owasp.org/www-community/attacks/xss/", 33)
  else
    puts "No XSS vulnerability found with payload: #{payload}"
  end
rescue => e
  puts colorize("Error during XSS check: #{e.message}", 31)
end

def csrf_check(url)
  response = Net::HTTP.get_response(URI(url))
  if response.body.include?('csrf_token')
    puts "No CSRF vulnerability found."
  else
    puts colorize("Possible CSRF vulnerability found.", 31)
    puts colorize("Cross-Site Request Forgery (CSRF) vulnerabilities occur when unauthorized commands are transmitted from a user that the web application trusts.", 33)
    puts colorize("Fix: Implement anti-CSRF tokens and ensure state-changing operations require a valid token. More info: https://owasp.org/www-community/attacks/csrf", 33)
  end
rescue => e
  puts colorize("Error during CSRF check: #{e.message}", 31)
end

def directory_bruteforce(url, wordlist)
  found_any = false
  wordlist.each do |word|
    test_url = "#{url}/#{word}"
    response = Net::HTTP.get_response(URI(test_url))
    if response.code.to_i == 200
      found_any = true
      puts colorize("Accessible directory or file found: #{test_url}", 31)
      puts colorize("Fix: Restrict access to sensitive directories and files, and use proper permissions and authentication mechanisms.", 33)
    end
  end
  puts colorize("No accessible directories or files found during brute force scan.", 32) unless found_any
rescue => e
  puts colorize("Error during Directory Bruteforce: #{e.message}", 31)
end

display_disclaimer
target_url = get_user_input

unless valid_url?(target_url)
  puts colorize("Invalid URL. Please enter a valid URL.", 31)
  exit
end

payloads_file = "payloads.txt"
wordlist_file = "bruteforce_wordlist.txt"
payloads = load_payloads(payloads_file)
wordlist = load_wordlist(wordlist_file)

if payloads[:sql_injection]
  puts "\nStarting SQL Injection Checks..."
  payloads[:sql_injection].each do |payload|
    sql_injection_check(target_url, "query", payload)
  end
else
  puts "No SQL Injection payloads found."
end

if payloads[:xss]
  puts "\nStarting XSS Checks..."
  payloads[:xss].each do |payload|
    xss_check(target_url, "query", payload)
  end
else
  puts "No XSS payloads found."
end

puts "\nStarting CSRF Check..."
csrf_check(target_url)

puts "\nStarting Directory Bruteforce..."
directory_bruteforce(target_url, wordlist)
