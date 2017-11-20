import yaml, os, scp, socket, logging

# Reading in config file for file paths and email info
from os import path

with open(path.join(path.dirname(__file__),"config.yml"), 'r') as ymlfile:
    cfg = yaml.safe_load(ymlfile)

LOG_FILENAME = 'deploy.log'
logging.basicConfig(filename=LOG_FILENAME,level=logging.DEBUG)

# Login Info
user = cfg['Login']['Username']
password = cfg['Login']['Password']

# for directories
src_dir = cfg['Directories']['Source']
server_dst_dir = cfg['Directories']['Server_Dest']

dst_ips_file = cfg['IP_File']['Server']
deploy_to_servers = cfg['IP_File']['Deploy_Server']
deploy_to_regs = cfg['IP_File']['Deploy_Reg']
lower_reg_range = cfg['IP_File']['Lower_Range']
upper_reg_range = cfg['IP_File']['Upper_Range']
reg_dest_dir = cfg['IP_File']['Reg_Dest']

if __name__ == "__main__":
    assert isinstance(deploy_to_regs, bool)
    assert isinstance(deploy_to_servers, bool)
    if not os.path.exists(src_dir):
        open(src_dir, 'w').close()

    if not os.path.exists(dst_ips_file):
        open(dst_ips_file, 'w').close()


    ip_list = []
    valid_regs = []

    with open(dst_ips_file, "r") as ip_file:
        lines = ip_file.readlines()
        for line in lines:
            ip_list.append(line.strip())


    if(deploy_to_regs):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for i in range (lower_reg_range,upper_reg_range+1):
            for ip in ip_list:
                octets = ip.split('.')
                netmask = octets[0]+'.'+octets[1]+'.'+octets[2]+'.'
            rep = os.system('ping -c 3 ' + (netmask+str(i)))
            if(rep == 0):
                valid_regs += netmask+i
            else:
                continue

        for ip in valid_regs:
            logging.info("Deploying to Register: "+ip)
            client = scp.Client(host=ip, user=user, password=password)
            client.transfer(src_dir, reg_dest_dir)

    if(deploy_to_servers):
        for ip in ip_list:
            logging.info("Deploying to Server: " + ip)
            client = scp.Client(host=ip, user=user, password=password)
            client.transfer(src_dir, server_dst_dir)