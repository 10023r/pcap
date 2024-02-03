
def parse_line(line, ips):
    ip_src, ip_dst, _, _, pckts, bytes_num = line.split(',')
    if ips.get(ip_src):
        ips[ip_src]['sent_pckts'] += int(pckts)
        ips[ip_src]['sent_bytes'] += int(bytes_num)
    else:
        ips[ip_src] = {
            "recieved_pckts": 0,
            "recieved_bytes": 0,
            "sent_pckts": int(pckts),
            "sent_bytes": int(bytes_num)
        }

    if ips.get(ip_dst):
        ips[ip_src]['recieved_pckts'] += int(pckts)
        ips[ip_src]['recieved_bytes'] += int(bytes_num)
    else:
        ips[ip_dst] = {
            "recieved_pckts": int(pckts),
            "recieved_bytes": int(bytes_num),
            "sent_pckts": 0,
            "sent_bytes": 0
        }
        pass


def write_line(f, ip_str, ips):
    info = ips[ip_str]
    line = f'{ip_str},{info["recieved_pckts"]},{info["recieved_bytes"]},{info["sent_pckts"]},{info["sent_bytes"]}\n'
    f.write(line)


def main():
    try:
        with open("../program1/prog1_res.csv") as file1, open("prog2_res.csv", "w") as file2:
            ip_map = {}
            for line in file1:
                parse_line(line, ip_map)

            for ip in ip_map:
                write_line(file2, ip, ip_map)

    except Exception as e:
        print(e)
    

if __name__ == "__main__":
    main()