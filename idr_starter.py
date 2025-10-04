from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET, gethostbyname

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53
cache = {}

def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  try:
      q = DNSRecord.question(domain, qtype=record_type)
      q.header.rd = 0  # Recursion Desired?  NO
      print("DNS query", repr(q))
      udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
      pkt, _ = udp_socket.recvfrom(8192)
      buff = DNSBuffer(pkt)

      header = DNSHeader.parse(buff)
      if q.header.id != header.id or header.rcode != RCODE.NOERROR:
        return None
      
      answers = []
      authority = []
      additional = []

      # Parse the question section #2
      for _ in range(header.q):
        DNSQuestion.parse(buff)

      # Parse the answer section #3
      for k in range(header.a):
        rr = RR.parse(buff)
        answers.append(rr)

      # Parse the authority section #4
      for k in range(header.auth):
        rr = RR.parse(buff)
        authority.append(rr)

      # Parse the additional section #5
      for k in range(header.ar):
        rr = RR.parse(buff)
        additional.append(rr)

      return {"answers": answers, "authority": authority, "additional": additional}

  except Exception:
    return None

def resolve(domain: str):
  
  while True:
    # Check cache first
    if domain in cache and "A" in cache[domain]:
      print(f"(Cache)found {domain} A")
      return cache[domain]["A"]
    
    # Start at root server
    server = ROOT_SERVER
    server_name = "root"
    
    # Split domain into parts (ex. gvsu.edu -> ['gvsu', 'edu'])
    domain_parts = domain.split('.')
    
    # Move through the domain hierarchy (sources 2 and 3 used here)
    for i in range(len(domain_parts)-1, -1, -1):
      # Piece together current domain from parts (ex. gvsu and edu -> gvsu.edu)
      curr_domain = '.'.join(domain_parts[i:]) 

      # Check cache for NS records of current domain
      if curr_domain in cache and "NS" in cache[curr_domain]:
        print(f"(Cache) found {curr_domain} NS")
        ns_cache = cache[curr_domain]["NS"]
        cache_ips = cache[curr_domain].get("NS_IP", {})
        
        # Use cache NS if available
        for ns in ns_cache:
          if ns in cache_ips:
            server = cache_ips[ns][0]
            server_name = ns
            print(f"(Cache) Using NS {ns} with IP {server}")
            break
        continue
      
      # Query current domain for NS records
      print(f"\n(Query) Asking {server_name} for {curr_domain} NS")
      response = get_dns_record(sock, curr_domain, server, 'NS')
      if response is None:
        return None
      
      # NS answers
      ns_answers = []
      for ans in response["answers"] + response["authority"]:
        if ans.rtype == QTYPE.NS:
          ns_answers.append(str(ans.rdata).rstrip('.'))
          
      if not ns_answers:
        print(f"No NS records found for {curr_domain}")
        break
        
      # IP addresses for NS
      ns_ips = {}
      for ans in response["additional"]:
        if ans.rtype == QTYPE.A and str(ans.rname).rstrip('.') in ns_answers:
          ns_ips[str(ans.rname).rstrip('.')] = [str(ans.rdata)]
    
    # Add answers to cache
      if curr_domain not in cache:
        cache[curr_domain] = {}
      cache[curr_domain]["NS"] = ns_answers
      cache[curr_domain]["NS_IP"] = ns_ips
      
    # Use NS answers to set next queried server
      next_server = None
      for ns in ns_answers:
        if ns in ns_ips:
          # ns_ips stores a list of IP strings; pick the first IP
          next_server = ns_ips[ns][0]
          server_name = ns
          break
      
      # If no next server, try to resolve NS hostname via gethostbynam from socket class
      if next_server is None:
        for ns in ns_answers:
          try:
            next_server = gethostbyname((ns).rstrip('.'))
            server_name = ns.rstrip('.').lower()
            break
          except Exception:
            continue
          
      # If still no next server, return None
      if next_server is None:
        return None
      
      server = next_server
    
    # Query A record from next server
    print(f"\n(Query) Asking {server_name} for {domain} A")
    response = get_dns_record(sock, domain, server, 'A')
    if response is None:
      return None
    
    # Look for CNAME (used resource 4 here)
    found_alias = False
    for ans in response.get("answers", []):
      if ans.rtype == QTYPE.CNAME:
        cname = str(ans.rdata.label).rstrip('.')
        print(f"Found CNAME for {domain}: {cname}")
        domain = cname
        found_alias = True
        break
      
    # If alias found, restart
    if found_alias:
      continue
      
    # Otherwise, if no CNAME, look for A records
    ip_addresses = []
    for ans in response["answers"]:
      if ans.rtype == QTYPE.A:
        ip_addresses.append(str(ans.rdata))

    if ip_addresses:
      if domain not in cache:
        cache[domain] = {}
      cache[domain]["A"] = ip_addresses
      return ip_addresses
    
    return None

# List cache
def list_cache():
  if cache is None or len(cache) == 0:
    print("Cache is empty")
    return []
  print("\nCache contents:")
  items = []
  idx = 1
  for domain, records in cache.items():
    for rtype, vals in records.items():
      print(f"{idx}: {domain} {rtype} -> {', '.join(vals)}")
      items.append((domain, rtype))
      idx += 1
  return items

# Clear cache
def clear_cache():
  cache.clear()
  print("Cache cleared")

# Remove cache entry N
def remove_cache_N(N):
  items = []
  for domain, records in cache.items():
    for remove in records.keys():
      items.append((domain, remove))

  if N < 1 or N > len(items):
    print(f"Invalid entry number: {N}")
    return

  domain, remove = items[N - 1]
  if remove in cache.get(domain, {}):
    del cache[domain][remove]
    if not cache[domain]:
      del cache[domain]
  print(f"Removed cache entry {N}: {domain} {remove}")

# Main loop
if __name__ == '__main__':
  sock = socket(AF_INET, SOCK_DGRAM)

  try:
    while True:
      domain = input("\nEnter a domain name or .exit > ").strip()
      if not domain:
        continue
      if domain == '.exit':
        break
      if domain == '.list':
        list_cache()
        continue
      if domain == '.clear':
        clear_cache()
        continue
      if domain.startswith('.remove'):
        split_input = domain.split()
        num = split_input[1]
        if num.isdigit():
          remove_cache_N(int(num))
        else:
          print("Invalid command. Usage: .remove N")
        continue
      ips = resolve(domain)
      if ips:
        print(f"\n(Result) {domain} -> {', '.join(ips)}")
      else:
        print(f"\n(Error) Failed to resolve {domain}")
  finally:
    sock.close()


"""

Resources Used:

1. https://pythontic.com/modules/socket/gethostbyname#google_vignette

2. https://artofproblemsolving.com/wiki/index.php/Range_function?srsltid=AfmBOor_-WXS4sGEHylIsS-87jOOKEF5MDyIjtaIHHeU49ln3JYJhUjv

3. https://realpython.com/python-join-string/#:~:text=Python's%20built%2Din%20string%20method,()%20to%20concatenate%20strings%20effectively.

4. https://stackoverflow.com/questions/14625693/find-http-and-or-www-and-strip-from-domain-leaving-domain-com

5. VSCode inline suggestions and Copilot for debugging and syntax help

"""