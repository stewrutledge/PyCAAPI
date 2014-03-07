#!/usr/bin/env python

from bottle import route, run, request, response
from sqlite3 import connect as sqconnect
from OpenSSL import crypto
from datetime import datetime
from ConfigParser import ConfigParser


config = ConfigParser()
config.readfp(open('pyca.cfg'))

conn = sqconnect('./ca.db')

caCertfile = config.get('ca', 'cacert')
caKeyfile = config.get('ca', 'cakey')
caKeypass = config.get('ca', 'passphrase')


def _create_db():
    cur = conn.cursor()
    cur.execute('''CREATE TABLE
            certs(
            domain TEXT,
            csr TEXT,
            cert TEXT,
            date TEXT,
            serial TEST,
            revoked INT)
            ''')
    cur.execute('''
            CREATE TABLE crl(
            crl TEXT)
            ''')
    conn.commit()
    cur.close()

caCert = crypto.load_certificate(
    crypto.FILETYPE_PEM,
    open(caCertfile).read()
    )
caKey = crypto.load_privatekey(
    crypto.FILETYPE_PEM,
    open(caKeyfile).read(),
    caKeypass
    )


@route('/newcert', method='POST')
def upload_ca():
    cur = conn.cursor()
    cur.execute('SELECT serial from certs order by ROWID desc limit 1')
    serialResp = cur.fetchone()
    if serialResp is None:
        serial = 1000
    else:
        serial = serialResp[0] + 1
    cert = crypto.X509()
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, request.body.read())
    cert.gmtime_adj_notAfter(365*24*60*60)
    cert.gmtime_adj_notBefore(0)
    cert.set_pubkey(csr.get_pubkey())
    cert.set_subject(csr.get_subject())
    cert.set_issuer(caCert.get_subject())
    cert.set_serial_number(serial)
    extensions = csr.get_extensions()
    extensions.append(crypto.X509Extension("crlDistributionPoints", False, "URI:http://localhost:8080/getcrl"))
    cert.add_extensions(extensions)
    cert.sign(caKey, 'sha256')
    signedCert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    rawCSR = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    commonName = csr.get_subject().CN
    cur = conn.cursor()
    cur.execute("SELECT * FROM certs WHERE domain = ? AND revoked = 0", (commonName, ))
    resp = cur.fetchone()
    print resp
    if resp is not None:
        return("This cert seems to already exist!\n")
        cur.close()
    cur = conn.cursor()
    cur.execute("INSERT INTO certs VALUES(?, ?, ?, ?, ?, ?)", (
        commonName,
        rawCSR,
        signedCert,
        str(datetime.now()),
        serial,
        0)
        )
    conn.commit()
    cur.close()
    response.status = 202
    return signedCert


@route('/revoke')
def revoke():
    commonName = (request.params.get('cn'), )
    revoked = crypto.Revoked()
    cur = conn.cursor()
    cur.execute('SELECT crl from crl')
    crlresp = cur.fetchone()
    if crlresp is None:
        crl = crypto.CRL()
    else:
        crl = crypto.load_crl(crypto.FILETYPE_PEM, crlresp[0])
    cur.execute("SELECT ROWID, serial FROM certs WHERE domain = ? and revoked = 0", commonName)
    resp = cur.fetchone()
    if resp is None:
        return("Cannot find cert in database \n")
    row_id = (resp[0], )
    serial = resp[1]
    revoked.set_serial(hex(serial).replace('0x', ''))
    revoked.set_rev_date(datetime.now().strftime('%Y%m%d%H%M%SZ'))
    revoked.set_reason('unspecified')
    crl.add_revoked(revoked)
    crl_out = (crl.export(crypto.FILETYPE_ANS1, caCert, caKey), )
    if crlresp is None:
        cur.execute('INSERT INTO crl VALUES(?)', crl_out)
    else:
        cur.execute('UPDATE crl SET crl=? where ROWID = 1', crl_out)
    cur.execute("UPDATE certs SET revoked=1 WHERE ROWID = ?", row_id)
    conn.commit()
    cur.close()
    return("Certificate revoked")


@route('/getcrl')
def get_crl():
    cur = conn.cursor()
    cur.execute('SELECT crl from crl where ROWID = 1')
    resp = cur.fetchone()
    if resp is None:
        return('No crl present')
    else:
        crl = crypto.load_crl(crypto.FILETYPE_PEM, resp[0])
        response.content_type = 'application/pkix-crl'
        return crl.export(caCert, caKey, crypto.FILETYPE_ASN1)


@route('/list')
def list_certs():
    limit = (int(request.params.get('limit', 10)), )
    cur = conn.cursor()
    cur.execute('SELECT domain, date, serial FROM certs limit ?', limit)
    resp = cur.fetchall()
    cur.close()
    certs = []
    if resp is not None:
        for cn in resp:
            certs.append({'cert': {
                'cn': cn[0],
                'serial': cn[2],
                'date': cn[1]
                }})
    return {'certs': certs}


@route('/get_cert')
def get_cert():
    cn = (request.params.get('cn'), )
    cur = conn.cursor()
    cur.execute('SELECT cert FROM certs WHERE domain = ?', cn)
    resp = cur.fetchone()
    if resp is not None:
        cert = resp[0]
        response.status = 200
        return('Cert for: %s \n' % cn + cert + '\n')
    else:
        response.status = 204
        return('No cert found for %s \n' % cn)


try:
    _create_db()
except Exception as e:
    print e
run()
