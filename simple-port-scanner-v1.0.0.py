import socket
import time # used only to emphasise the permission warning
import ipaddress #used to validate input for target IP

def scan(host, port): # actual port-scanning function
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: #Creates new socket. 'with' handles the management of the socket so it doesn't need to be closed manually. New socket now referred to as 's'
        s.settimeout(1)  # 1 second timeout for new socket ('s') connections. Scanner will wait for 1 second for a response from port
        return s.connect_ex((host, port)) == 0  # socket attempts TCP handshake and returns the port's response. True if open, False if closed

def check_if_valid_IP_addr(target): # checks if IP entered is valid
    try:
        ipaddress.IPv4Address(target) # Uses ipaddress module to check parameter is valid. This function only returns True or False .
        return True
    except ValueError:
        return False

print("\n*** Welcome to this basic port scanner ***\n")
time.sleep(0.5) # half second delay
print("---> WARNING: This scanner can only be used on your own personal network,\n or a network that you have permission to scan\n")
time.sleep(2) # an attempt to get user to read the warning

WELL_KNOWN = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 3389] #default ports to scan i.e 'well-known' ports
permission = input("Do you have permission to scan the target network?\n >>> Y / N \n > ").strip().upper()

if permission == "Y":
    is_scanning = True
    while is_scanning: # main loop
       
        target = "" #
        while target == "": #forces user to enter an valid IP
            target = input("\n- Target IP -\n You must enter an IP to proceed. \n Enter the target IP:  (e.g., 127.0.0.1)\n > ").strip() #target IP to scan
            check_if_valid_IP_addr(target) # Checks if argument (user's IP input, 'target') is a valid IPv4 addr
            if not check_if_valid_IP_addr(target): # If invalid, show error
                print("ERROR! \nInvalid IP. Try again. \n")
                target = ""

        choice = "" #forces user to enter a choice for custom ports or default well-known list
        while choice == "":
           choice = input(f"\n- Port selection - \nEnter 'c' to select (c)ustom ports or 'w' for (w)ell-known ports \n Well-known ports are {WELL_KNOWN}\n\n > ").strip().lower()   # User enters 'c' to enter custom ports or 'w' for default/well_known ports
        
        if choice == "c": #If the user wants to enter custom port selection: 
            custom_port_input = input("Enter the ports you wish to scan. \nEnsure they are seperated with a single space e.g. 80 443 8080: \n > ")
            ports = []
            for each_port in custom_port_input.split(): #Adds custom port selection to variable that stores what ports to be scanned
                ports.append(int(each_port))
       
        elif choice == "w": # Chooses the default port selection
            print("Well-known ports chosen to be scanned.")
            ports = WELL_KNOWN

        else: # Defaults to default/well-known ports if invalid selection made
            print(f"Invalid selection. Defaulting to scan well-known ports on target...")
            ports = WELL_KNOWN

        print(f"\nScanning target IP {target}...") # Indicates scan has started and confirms IP it is scanning
        
        open_ports = []         #Lists are reset on each pass so future passes don't use previous results
        closed_ports = []

        for each_port in ports: #loop scans each entry in 'ports' list for the target IP, appends it to the open_ports list if it is open, appends to closed_ports if not
            if scan(target, each_port):
                open_ports.append(each_port)
            else:
                closed_ports.append(each_port)

        print("\n >>>> Scan Results >>>> ") #results displayed
        print(f"Open  : {open_ports}") 
        print(f"Closed: {closed_ports}")
        print("\n- If there are no open ports, ensure host is up are IP is correct.")

        if input("\nScan again? (type 'y' to scan again, or any other letter to quit): ").strip().upper() == "Y":
            continue #restarts loop
        else: 
            print("Exiting...")
            break #exits loop

elif permission == "N":
    print("You must have permission to scan the network. Exiting...")

else: 
    print("Invalid entry. Exiting...")