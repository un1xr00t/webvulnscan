require 'net/http'
require 'uri'
require 'nokogiri'
require 'cgi'

def colorize(text, color_code)
  "\e[#{color_code}m#{text}\e[0m"
end

def display_banner
  banner = <<~BANNER
    ██▒   █▓ █    ██  ██▓     ███▄    █   ██████  ▄████▄   ▄▄▄       ███▄    █ 
    ▓██░   █▒ ██  ▓██▒▓██▒     ██ ▀█   █ ▒██    ▒ ▒██▀ ▀█  ▒████▄     ██ ▀█   █ 
    ▓██  █▒░▓██  ▒██░▒██░    ▓██  ▀█ ██▒░ ▓██▄   ▒▓█    ▄ ▒██  ▀█▄  ▓██  ▀█ ██▒
      ▒██ █░░▓▓█  ░██░▒██░    ▓██▒  ▐▌██▒  ▒   ██▒▒▓▓▄ ▄██▒░██▄▄▄▄██ ▓██▒  ▐▌██▒
       ▒▀█░  ▒▒█████▓ ░██████▒▒██░   ▓██░▒██████▒▒▒ ▓███▀ ░ ▓█   ▓██▒▒██░   ▓██░
       ░ ▐░  ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
       ░ ░░  ░░▒░ ░ ░ ░ ░ ▒  ░░ ░░   ░ ▒░░ ░▒  ░ ░  ░  ▒     ▒   ▒▒ ░░ ░░   ░ ▒░
         ░░   ░░░ ░ ░   ░ ░      ░   ░ ░ ░  ░  ░  ░          ░  ░         ░ 
          ░     ░         ░  ░         ░       ░  ░ ░            ░  ░         ░ 
         ░                                        ░                             
  BANNER
  puts colorize(banner, 31)
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
  "http://#{domain}"
end

def valid_url?(url)
  begin
    uri = URI(url)
    uri.is_a?(URI::HTTP) || uri.is_a?(URI::HTTPS)
  rescue URI::InvalidURIError
    false
  end
end

def load_payloads(file_path)
  # Replace this with your payload loading logic
  # Example:
  payloads = {
    sql_injection: ["' OR 1=1 --", "'; DROP TABLE users; --"],
    xss: ["<script>alert('XSS')</script>"]
  }
  payloads
end

def load_wordlist(file_path)
  # Replace this with your wordlist loading logic
  wordlist = ["admin", "login", "password"]
  wordlist
end

def fetch_with_redirect(uri, limit = 10)
  raise 'Too many HTTP redirects' if limit == 0

  response = Net::HTTP.get_response(uri)
  case response
  when Net::HTTPSuccess then response
  when Net::HTTPRedirection then
    location = response['location']
    warn "Redirected to #{location}"
    new_uri = URI(location)
    fetch_with_redirect(new_uri, limit - 1)
  else
    response.error!
  end
end

def check_vulnerability(url, method, param, payloads)
  payloads.each do |payload|
    escaped_payload = URI.encode_www_form_component(payload)
    uri = URI("#{url}?#{param}=#{escaped_payload}")
    puts "Testing URL: #{uri}"
    begin
      response = fetch_with_redirect(uri)
      # Implement vulnerability checks based on response
      # Example:
      if method == "SQL Injection" && response.body.include?("SQL syntax")
        puts colorize("Possible SQL Injection vulnerability found: #{payload}", 31)
      elsif method == "XSS" && response.body.include?(payload)
        puts colorize("Possible XSS vulnerability found: #{payload}", 31)
      else
        puts colorize("No #{method} vulnerability detected for payload: #{payload}", 32)
      end
    rescue => e
      puts colorize("Error during #{method} check: #{e.message}", 31)
    end
  end
end

display_banner

puts colorize("Version 2.0", 34)
puts colorize("Created by un1xr00t", 34)
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

if payloads && payloads[:sql_injection]
  puts "\nStarting SQL Injection Checks..."
  check_vulnerability(target_url, "SQL Injection", "query", payloads[:sql_injection])
else
  puts "No SQL Injection payloads found."
end

if payloads && payloads[:xss]
  puts "\nStarting XSS Checks..."
  check_vulnerability(target_url, "XSS", "query", payloads[:xss])
else
  puts "No XSS payloads found."
end

# ... (CSRF and Directory Bruteforce checks with similar error handling)
