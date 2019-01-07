# RidRelay
Quick and easy way to get domain usernames while on an internal network.

Hit me up: [@skorov8](https://twitter.com/skorov8)

## How it works
RidRelay combines the NTLM Relay attack, common lsarpc based queries and RID cycling to get a list of domain usernames. It takes these steps:
1. Spins up an SMB and HTTP servers and waits for an incoming connection
2. The incoming credentials are relayed to a specified target, creating a connection with the context of the relayed user
3. Queries are made down the SMB connection to the lsarpc pipe to get the list of domain usernames. This is done by cycling up to 50000 RIDs
4. The password policy is extracted through the samr pipe

(For best results, use with Responder)

## Dependencies
* Python 2.7 (sorry but only the unreleased [__python36__ branch](https://github.com/SecureAuthCorp/impacket/tree/python36) if Impacket will play nice with 3 :( )
* Impacket v0.9.17 or above

## Installation
```
pipenv install --two
pipenv shell

# Optional: Run if installing impacket
git submodule update --init --recursive
cd submodules/impacket
python setup.py install
cd ../..
```

## Usage
First, find a target host to relay to. The target must be a member of the domain and MUST have SMB Signin off. [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) can get this info for you very quick!

Start RidRelay pointing to the target:
```
python ridrelay.py -t 10.0.0.50
```
OR

Also output usernames to file
```
python ridrelay.py -t 10.0.0.50 -o path_to_output.txt
```

**Highly Recommended:** Start [Responder](https://github.com/SpiderLabs/Responder) to trick users to connecting to RidRelay

## Shout out
Mad props go to:
* Ronnie Flathers ([@ropnop](https://twitter.com/ropnop)) - Original idea on low priv smb relaying

## TODO:
* Add password policy enumeration *DONE*
* Dynamic relaying based on where incoming creds have admin rights
* Getting active sessions???
* Connect with Bloodhound???
