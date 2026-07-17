'''
Contains HEADER as a source of truth.
'''

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US, en;q=0.9",
}

'''
This is a very long description of a header.
This is a constant HEADER in Python for sending requests to a website via curl_cffi.
The User-Agent part of the dictionary is to act as a chrome browser on a Windows 10/11 machine.
This is because Google Chrome is the most used browser, and Windows make up 56-70% of PCs globally.
What is a 'dictionary'?
A dictionary is a mutable data form in Python that uses key and value pairs.
What is 'Python'?
Python is a programming language built on the C coding language. It is widely considered one of the easiest languages to learn in the world.
Python is mostly used as a backend language, similar to Go, JavaScript(Node.js), and PHP.
C is a language that is quite old but still widely used. It is built on Assembly, one of the most complex languages.
Assembly is complex and tedious to code because you are required to manually manage the memory of the computer.

Now, why is this HEADER important?
It is important as having the Accept-Language and the User-Agent make it seem like a real browser, which allows it to bypass simple CAPTCHAs and anti-bot software.
It is inside a completely different config file so that it can be imported to other files and is modified throughout all files.
'''