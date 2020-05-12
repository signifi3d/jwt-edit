A quick JWT token editor. Very naive implementation, you are responsible for correctly formatting your input. Only implements "none" or "HS256" encryption types because I'm lazy. Might add more later

usage: jwt-edit.py [-h] -t TOKEN [-d DATA [DATA ...]] [-i IAT] [-x EXP]  
                   [-a {none,HS256}] [-k KEY]  

optional arguments:  
  -h, --help            show this help message and exit  
  -t TOKEN, --token TOKEN  
                        JWT token  
  -d DATA [DATA ...], --data DATA [DATA ...]  
                        Space-separated fields to add or edit in the payload.
                        Formatted field:value  
  -i IAT, --iat IAT     Issued at time, can be now to use current time or a
                        specified Unix time.  
  -x EXP, --exp EXP     Expiration time, can be an offset in minutes from the
                        iat by prefixing with + or a valid Unix time.  
  -a {none,HS256}, --alg {none,HS256}  
                        Signature encryption algorithm.  
  -k KEY, --key KEY     Encryption key.  
  -p, --print           Print token contents before processing.

