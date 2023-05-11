fid = open("xmpls_from_DOIP_Guide_normalized.txt","r")
fod = open("xx","w")

for line in fid.readlines():
    if line[:-1].strip() == "":
        continue
    if len(line.split("_")) == 2:
        fod.close()
        fn = line.strip().split(":")[0] + ".doip"
        fod = open(fn,"w")
    else:
        print (">>>" + line[:-1])
        fod.write(line)
