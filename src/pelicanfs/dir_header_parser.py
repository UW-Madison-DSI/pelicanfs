
def parse_metalink(headers={}):
    """
    Parse the metalink headers to get a list of caches to attempt to try in priority orider
    """
    linkPrio = []

    if "Link" in headers:
        links = headers["Link"].split(",")
        for mlink in links:
            elmts = mlink.split(";")
            mdict = {}
            for elm in elmts[1:]:
                left, right = elm.split("=", 1)
                mdict[left.strip()] = right.strip()
            
            priority = len(headers)
            if mdict["pri"]:
                priority = int(mdict["pri"])
            
            link = elmts[0].strip(" <>")

            linkPrio.append([link, priority])

    linkPrio.sort(key=lambda x: x[1])
    return linkPrio

def get_dirlist_loc(headers={}):
    """
    Parse the headers to get the dirlist location

    This will None if there is no dirlist location
    """
    if "X-Pelican-Namespace" in headers:
        namespace = headers["X-Pelican-Namespace"]
        elmts = namespace.split(", ")
        for elm in elmts:
            left, right = elm.split("=", 1)
            if left == "collections-url":
                return right
        
    
    return None