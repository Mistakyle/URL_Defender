
# whois is not support on Windows 10 -> or in Python 3.5 +...
import whois

w = whois.query('pythonforbeginners.com')

print(w)
