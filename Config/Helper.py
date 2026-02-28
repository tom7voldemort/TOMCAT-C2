#!/usr/bin/python3

Helper = """
    Options:
        --mtls                   :     Start Server With MTLS Socket.
        -M / --meterpreter       :     Start Server With TLV Socket: Metasploit Payload & Reverse Shell Tools Support.
        -S / --server-host       :     Server Host Address.
        -w / --host              :     Server Flask Web GUI Host
        -p / --port              :     Server Flask Web GUI Port
        
    Certificate Setup:
        -i / --init-certs        :     Initialize MTLS Certificate.

    Agent Options:
        -a / --gen-agent         :     Generate Agent.
        -m / --gen-multi-agent   :     Generate Multi Agent.
        -c / --gen-agent-count   :     Agent Count For Generate Multi Agent.
        -u / --gen-agent-prefix  :     Agent Prefix Name / ID.
        -l / --list-agent        :     List Available Agent.
        -r / --revoke-agent      :     Revoke Agent From Server.
        -ah / --agent-host       :     Server Host Address For Agent.
        -ap / --agent-port       :     Server Port Address For Agent.
        -am / --agent-mtls       :     Enabling MTLS Mode For Agent.
        -ps / --add-persistence  :     Enabling Persistence Mode For Agent.
        -hc / --hide-console     :     Hide Agent Process Console. ( Windows Only )



    EXAMPLE OF USE:
    Certificate Built:
        [i] Generate Certificates For Server & Agent.
        python3 start.py -i

    Start Server:
        [i] Start Server In Default Mode. [ Not Secure ]:
            python3 start.py
            
        [i] Start Server With Metasploit Meterpreter Payload & Another Reverse Shell Tools Support Mode. [ Not Secure ]:
            python3 start.py -M
        
        [i] Start Server With MTLS Mode. [ Secure ]:
            python3 start.py --mtls
        
        [i] Custom Web Panel Setup:
            python3 start.py -w <web host ip address> -p <web host port>
            python3 start.py -w <web host ip address> -p <web host port> -M
            python3 start.py -w <web host ip address> -p <web host port> --mtls

    Built Agent:
        [i] Built Single Agent:
        - Default:
            python3 start.py -a <agent id> -ah <agent host> -ap <agent port>
        - With MTLS:
            python3 start.py -a <agent id> -ah <agent host> -ap <agent port> -am
        - With Persistence:
            python3 start.py -a <agent id> -ah <agent host> -ap <agent port> -ps
        - With Hide Console:
            python3 start.py -a <agent id> -ah <agent host> -ap <agent port> -hc
        - Complex:
            python3 start.py -a <agent id> -ah <agent host> -ap <agent port> -am -ps -hc

        [i] Built Multi Agent:
        - Default:
            python3 start.py -m -c <agent count> -ah <agent host> -ap <agent port>
        - With MTLS:
            python3 start.py -m -c <agent count> -ah <agent host> -ap <agent port> -am
        - With Prefix Name:
            python3 start.py -m -c <agent count> -ah <agent host> -ap <agent port> -u <prefix name>
        - With Persistence:
            python3 start.py -m -c <agent count> -ah <agent host> -ap <agent port> -ps
        - With Hide Console:
            python3 start.py -m -c <agent count> -ah <agent host> -ap <agent port> -hc
        - Complex:
            python3 start.py -m -c <agent count> -ah <agent host> -ap <agent port> -u <prefix name> -am -ps -hc
                
"""
