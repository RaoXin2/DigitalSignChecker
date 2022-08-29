import pefile
from OpenSSL import crypto
from OpenSSL.crypto import _lib, _ffi, X509
import os
import openpyxl

TARGET_SIGN_NAME = 'Siemens AG'
BASE_DIR = 'D:/Program Files/Siemens/Automation/AI Model Deployer'
FILES_CHECKING_LIST = 'file_list.txt'


def get_certificates(self):
    certs = _ffi.NULL
    if self.type_is_signed():
        certs = self._pkcs7.d.sign.cert
    elif self.type_is_signedAndEnveloped():
        certs = self._pkcs7.d.signed_and_enveloped.cert


    pycerts = []
    for i in range(_lib.sk_X509_num(certs)):
        pycert = X509.__new__(X509)
        pycert._x509 = _lib.sk_X509_value(certs, i)
        pycerts.append(pycert)

    if not pycerts:
        return None
    return tuple(pycerts)


def get_digital_signature_from_file(signedFile):
    try:
        pe = pefile.PE(signedFile)
    except:
        return ['No such file']


    address = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ].VirtualAddress
    size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ].Size

    if address == 0:
        return ['Source file not signed']
    else:
        signature = pe.write()[address + 8:]

    pkcs = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, bytes(signature))
    certs = get_certificates(pkcs)
    cert_list = []
    for cert in certs:
        c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
        a = crypto.load_certificate(crypto.FILETYPE_PEM, c)
        # get data from parsed cert
        sbj = a.get_subject()
        if sbj.O != TARGET_SIGN_NAME:
            continue
        else:
            cert_list.append(signedFile.replace(BASE_DIR, ''))
            cert_list.append(sbj.O)  # organization
            cert_list.append(str(a.get_subject()))
            cert_list.append(str(a.get_version()))
            cert_list.append(str(a.get_issuer()))
            cert_list.append(str(a.get_signature_algorithm(), 'utf-8'))  # encrpt method
            cert_list.append(format(a.get_serial_number(), 'X'))  # serial number
        # if sbj.O == 'DigiCert, Inc.':
        #     continue
        # else:
        #     print(format(a.get_serial_number(), 'X'))
        #     print(a.get_signature_algorithm())
        #     print(sbj.O)
        #     print(sbj.CN)
        #     print('=========')

    if len(cert_list) == 0:
        cert_list.append('-')
        cert_list.append('-')
        cert_list.append('-')
        cert_list.append('-')
        cert_list.append('-')

    return cert_list

file1 = open(FILES_CHECKING_LIST, 'r')
lines = file1.readlines()
file1.close()

workbook = openpyxl.Workbook()
sheet = workbook.active  # 获取活动表
sheet.append(
    ['File name', 'Organization', 'Subject', 'Version', 'Issuer', 'Algorithm', 'Serial number'])
for line in lines:
    path = os.path.join(BASE_DIR, line).strip().replace('\\', '/')
    output = line.strip() + ','
    dsInfo = get_digital_signature_from_file(path)
    sheet.append(dsInfo)

workbook.save('AIModelDeployer_DigitalSignatureCheck.xlsx')
