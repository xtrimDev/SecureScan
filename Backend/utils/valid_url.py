import re

def is_valid_url(url):
    pattern = re.compile(
        r'^(http|https)://'  
        r'([a-zA-Z0-9.-]+)' 
        r'(\.[a-zA-Z]{2,})' 
        r'(:\d+)?'           
        r'(\/.*)?$' 
    )

    return pattern.match(url) is not None