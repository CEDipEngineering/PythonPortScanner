import tkinter as tk
import re
import socket
import time

class Application:
    
    def __init__(self, master=None):
        # From https://web.mit.edu/rhel-doc/4/RH-DOCS/rhel-sg-en-4/ch-ports.html
        self.port_names_dict = {
            20:"FTP",
            21:"FTP",
            23:"TELNET",
            53:"DNS",
            67:"DHCP",
            68:"DHCP",
            80:"HTTP",
            22:"SSH",
            123:"NTP",
            135:"NetBIOS",
            136:"NetBIOS",
            137:"NetBIOS",
            138:"NetBIOS",
            139:"NetBIOS",
            443:"HTTPS",
            514:"Shell",
            3306:"MySQL",
            5432:"Postgres",
            5433:"Postgres"
        }

        self.master = master
        self.widget1 = tk.Frame(self.master)
        self.widget1.pack()
        self.labelString = tk.StringVar()

        self.game = tk.Label(self.widget1, text = 'Python Port Scanner')
        self.game["font"] = ("Verdana", "36", "bold")
        self.game.config(anchor=tk.CENTER)
        self.game.pack(pady=20)

        self.widget2 = tk.Frame(self.widget1, width=600, height=400)
        self.widget2
        c = tk.Label(self.widget2 ,text = "IP address").grid(row = 0,column = 0)
        a = tk.Label(self.widget2 ,text = "Port Range Start").grid(row = 1,column = 0)
        b = tk.Label(self.widget2 ,text = "Port Range End").grid(row = 2,column = 0)
        self.IP = tk.Entry(self.widget2)
        self.IP.grid(row = 0,column = 1)
        self.PStart = tk.Entry(self.widget2)
        self.PStart.grid(row = 1,column = 1)
        self.PEnd = tk.Entry(self.widget2)
        self.PEnd.grid(row = 2,column = 1)
        self.widget2.pack()

        self.labelError = tk.Label(self.widget1, textvariable=self.labelString)
        self.labelError["font"] = ("Verdana", "16", "bold")
        self.labelError.pack()

        self.button = tk.Button(self.widget1)
        self.button["text"] = "Go"
        self.button["font"] = ("Cambria", "16", "bold")
        self.button["width"] = 24
        self.button["command"] = self.validateinput
        self.button.config(anchor=tk.CENTER)    
        self.button.pack(side=tk.BOTTOM, pady=20)
    
    def validateinput(self):
        IP = self.IP.get()
        PortStart = self.PStart.get()
        PortEnd = self.PEnd.get()
        # print(IP)
        if re.match("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}", IP) is None and re.match("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/24", IP) is None:
            self.labelString.set("InvalidIPAddress")
            return
        if re.match("[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/24", IP) is not None:
            IP_base = IP.split(".")[:-1] # Discard last element
            # print(IP_base)
            IP_base = ".".join(IP_base)
            IP_List = [IP_base + "." + str(x) for x in range(1,255)]
            # print(IP_List)
            # self.master.destroy()
        else:
            IP_List = [IP]
        try:
            PortStart = int(PortStart)
            PortEnd = int(PortEnd)
            if PortStart>PortEnd or PortStart<0 or PortStart>65535 or PortEnd<0 or PortEnd>65535:
                raise ValueError
        except ValueError:
            self.labelString.set("Port Values must be in proper order\n (Start < End) and be proper integers\nin range 0-65535")
            return
        
        self.labelString.set(f"Beginning Port Scan for ports {PortStart}:{PortEnd} inclusive\nTarget IP: {IP}")
        for ip in IP_List:
            self.scanPorts(ip, PortStart, PortEnd)
        

    def scanPorts(self, IP, PortStart, PortEnd):
        # Based on the "Violent Python - A Cookbook for Hackers [...]" book, by TJ. O`Connor 
        successes = {}
        p = PortStart
        while p < PortEnd:
            x = self.retBanner(IP, p)
            if x is not None:
                successes[p] = x
            p += 1
        if len(successes.values()) > 0: # If no hits, dont write file
            with open(f"./output_{IP.replace('.', '_')}.txt", "w") as f:
                f.write(f"Log for IP {IP}\n")
                for k,v in successes.items():
                    if k in self.port_names_dict.keys():
                        f.write(f"Port: {k}({self.port_names_dict[k]})\tReturned: {v}\n")
                    else:
                        f.write(f"Port: {k}\tReturned: {v}\n")
        # print(IP, successes.values())
    def retBanner(self, IP, port):
        try:
            print(f"Connecting to {IP}:{port}") 
            socket.setdefaulttimeout(0.5)
            s = socket.socket()
            s.connect((IP,port))
            x = s.recv(1024)
            s.close()
            return x
            
        except Exception as e:
            print(e)
            return None


def Main(app = None): 
    main_window = tk.Tk()
    main_window.geometry("1280x720")
    app_1 = Application(main_window)
    main_window.mainloop()

if __name__ == "__main__":
    Main()