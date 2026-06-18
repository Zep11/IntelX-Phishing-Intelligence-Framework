

def check_url_length(url):
    length=len(url)

    return{
        "length" : length ,
        "its_long" : length > 75
    }
