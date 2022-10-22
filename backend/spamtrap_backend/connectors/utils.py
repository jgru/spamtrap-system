def read_whitelist(fp):
    wl = []
    if fp:
        with open(fp, "r") as f:
            for line in f.readlines():
                wl.append(line.strip())
    return wl
