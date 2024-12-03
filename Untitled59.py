#!/usr/bin/env python
# coding: utf-8

# In[101]:


log_file = 'sample.log'


# In[102]:


import csv


# In[103]:


with open(log_file, 'r') as file:
    def count_requests(log_lines):
        ip_request_counts = {}
        # Process each log line
        for line in log_lines:
            ip = line.split()[0] # Extract the IP address
            if ip in ip_request_counts:
                ip_request_counts[ip] += 1  # Increment count for existing IP
            else:
                ip_request_counts[ip] = 1  # Initialize count for new IP
        print(f"{'IP Address':<20}{'Request Count'}")
        for ip, count in ip_request_counts.items():
            print(f"{ip:<20}{count}")
        return ip_request_counts
    requests_per_ip = count_requests(file)


# In[104]:


with open(log_file, 'r') as file:
    def endpoint_access_count(log_lines):
        endpoint_count = {}
        # Process each log line
        for line in log_lines:
            endpoint = line.split()[6] #extracting endpoints
            if endpoint in endpoint_count:
                endpoint_count[endpoint] += 1  # Increment count for existing endpoint
            else:
                endpoint_count[endpoint] = 1  # Initialize count for new endpoint
        print("Most Frequently Accessed Endpoint:")
        l = sorted(endpoint_count.items(), key=lambda item: item[1], reverse=True)[0] #sorting the dictionary by values in desc order
        print(l[0].strip('"')+" "+ f"(Accessed {l[1]} times)")
        return endpoint_count
    most_accessed_endpoints = endpoint_access_count(file)


# In[105]:


with open(log_file, 'r') as file:
    def detect_suspicious_activity(log_lines, threshold=6): # default threshold is 10 but taken configured threshold 6
        failed_login_counts = {}

        # Process each log line
        for line in log_lines:
            # Check if the log line indicates a failed login 
            if "401" in line or "Invalid credentials" in line:
                ip = line.split()[0]  # Extract the IP address
                if ip in failed_login_counts:
                    failed_login_counts[ip] += 1  # Increment count for existing IP
                else:
                    failed_login_counts[ip] = 1  # Initialize count for new IP
        
    
        # Filter out IP addresses that do not meet the threshold for failed logins
        flagged_ips = {ip: count for ip, count in failed_login_counts.items() if count > threshold}

        # Display the flagged IPs and their failed login counts
        print("Suspicious Activity Detected:")
        if flagged_ips:
            print(f"{'IP Address':<20}{'Failed Login Attempts'}")
            for ip, count in flagged_ips.items():
                print(f"{ip:<20}{count}")
        else:
            print("No suspicious login attempts detected.")
        return failed_login_counts
    suspicious_activity = detect_suspicious_activity(file)
    


# In[106]:


# Saving the results to a CSV file
with open('log_analysis_results.csv', mode='w', newline='') as file:
    file = csv.writer(file)
    
    # Requests per IP
    file.writerow(['Requests per IP:'])
    file.writerow(['IP Address', 'Request Count'])
    for ip, count in requests_per_ip.items():
        file.writerow([ip, count])
    
    # Most Accessed Endpoint
    file.writerow(['Most Accessed Endpoint:'])
    file.writerow(['Endpoint', 'Access Count'])
    for endpoint, count in most_accessed_endpoints.items():
        file.writerow([endpoint, count])
    
    # Suspicious Activity
    file.writerow(['Suspicious Activity:'])
    file.writerow(['IP Address', 'Failed Login Count'])
    for ip, count in suspicious_activity.items():
        file.writerow([ip, count])


# In[ ]:




