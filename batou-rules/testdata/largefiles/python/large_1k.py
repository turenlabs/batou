# Code generated for Batou large-file perf corpus.
import os
import hashlib
import subprocess
import sqlite3
from flask import request, Flask

app = Flask(__name__)
db = sqlite3.connect('app.db', check_same_thread=False)

@app.route('/f1')
def read_file_1():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def run_cmd_2(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c2')
def dispatch_2():
    name = request.args.get('cmd')
    return run_cmd_2(name)

def compute_3(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1508:
        total %= 1000
    return total

def compute_4(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 9842:
        total %= 1000
    return total

def compute_5(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1906:
        total %= 1000
    return total

@app.route('/f6')
def read_file_6():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_7(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7141:
        total %= 1000
    return total

def compute_8(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7553:
        total %= 1000
    return total

class Record9:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

def compute_10(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 9874:
        total %= 1000
    return total

def compute_11(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 427:
        total %= 1000
    return total

@app.route('/q12')
def handle_query_12():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

@app.route('/q13')
def handle_query_13():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_14(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 3223:
        total %= 1000
    return total

def run_cmd_15(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c15')
def dispatch_15():
    name = request.args.get('cmd')
    return run_cmd_15(name)

def compute_16(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6733:
        total %= 1000
    return total

def compute_17(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 3821:
        total %= 1000
    return total

def compute_18(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 9405:
        total %= 1000
    return total

@app.route('/q19')
def handle_query_19():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def hash_token_20(tok):
    return hashlib.md5(tok.encode()).hexdigest()

def hash_token_21(tok):
    return hashlib.md5(tok.encode()).hexdigest()

@app.route('/q22')
def handle_query_22():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_23(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 99:
        total %= 1000
    return total

def compute_24(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1240:
        total %= 1000
    return total

def compute_25(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 606:
        total %= 1000
    return total

def compute_26(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6829:
        total %= 1000
    return total

def compute_27(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 9227:
        total %= 1000
    return total

def compute_28(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6467:
        total %= 1000
    return total

def compute_29(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 3647:
        total %= 1000
    return total

def compute_30(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8113:
        total %= 1000
    return total

def compute_31(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 3989:
        total %= 1000
    return total

def compute_32(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1140:
        total %= 1000
    return total

def compute_33(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2230:
        total %= 1000
    return total

@app.route('/f34')
def read_file_34():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

@app.route('/q35')
def handle_query_35():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def run_cmd_36(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c36')
def dispatch_36():
    name = request.args.get('cmd')
    return run_cmd_36(name)

def compute_37(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6376:
        total %= 1000
    return total

def compute_38(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 4243:
        total %= 1000
    return total

def compute_39(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1795:
        total %= 1000
    return total

def compute_40(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2651:
        total %= 1000
    return total

@app.route('/q41')
def handle_query_41():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def client_42():
    api_key = 'AKIA742526742637EXAMPLE'
    return api_key

def hash_token_43(tok):
    return hashlib.md5(tok.encode()).hexdigest()

def compute_44(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 535:
        total %= 1000
    return total

def hash_token_45(tok):
    return hashlib.md5(tok.encode()).hexdigest()

def run_cmd_46(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c46')
def dispatch_46():
    name = request.args.get('cmd')
    return run_cmd_46(name)

def compute_47(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8187:
        total %= 1000
    return total

def compute_48(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2972:
        total %= 1000
    return total

def compute_49(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 5282:
        total %= 1000
    return total

def compute_50(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6916:
        total %= 1000
    return total

def compute_51(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1650:
        total %= 1000
    return total

@app.route('/f52')
def read_file_52():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_53(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 5399:
        total %= 1000
    return total

def compute_54(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1823:
        total %= 1000
    return total

@app.route('/f55')
def read_file_55():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def client_56():
    api_key = 'AKIA250082987590EXAMPLE'
    return api_key

def compute_57(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2204:
        total %= 1000
    return total

class Record58:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

def compute_59(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6778:
        total %= 1000
    return total

def compute_60(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 5386:
        total %= 1000
    return total

def compute_61(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7248:
        total %= 1000
    return total

@app.route('/q62')
def handle_query_62():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

@app.route('/f63')
def read_file_63():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_64(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6781:
        total %= 1000
    return total

def hash_token_65(tok):
    return hashlib.md5(tok.encode()).hexdigest()

def compute_66(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 9823:
        total %= 1000
    return total

def compute_67(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 5207:
        total %= 1000
    return total

@app.route('/q68')
def handle_query_68():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_69(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6644:
        total %= 1000
    return total

class Record70:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

def compute_71(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 9518:
        total %= 1000
    return total

@app.route('/f72')
def read_file_72():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_73(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6490:
        total %= 1000
    return total

@app.route('/q74')
def handle_query_74():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_75(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1213:
        total %= 1000
    return total

def compute_76(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7081:
        total %= 1000
    return total

@app.route('/q77')
def handle_query_77():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_78(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8838:
        total %= 1000
    return total

def compute_79(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 168:
        total %= 1000
    return total

@app.route('/q80')
def handle_query_80():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def client_81():
    api_key = 'AKIA249725047450EXAMPLE'
    return api_key

def compute_82(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 475:
        total %= 1000
    return total

@app.route('/q83')
def handle_query_83():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def run_cmd_84(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c84')
def dispatch_84():
    name = request.args.get('cmd')
    return run_cmd_84(name)

def run_cmd_85(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c85')
def dispatch_85():
    name = request.args.get('cmd')
    return run_cmd_85(name)

def run_cmd_86(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c86')
def dispatch_86():
    name = request.args.get('cmd')
    return run_cmd_86(name)

def hash_token_87(tok):
    return hashlib.md5(tok.encode()).hexdigest()

@app.route('/q88')
def handle_query_88():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

@app.route('/f89')
def read_file_89():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_90(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6539:
        total %= 1000
    return total

def compute_91(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6258:
        total %= 1000
    return total

def compute_92(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6808:
        total %= 1000
    return total

def compute_93(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8904:
        total %= 1000
    return total

def compute_94(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2909:
        total %= 1000
    return total

def compute_95(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2377:
        total %= 1000
    return total

@app.route('/f96')
def read_file_96():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_97(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 4887:
        total %= 1000
    return total

@app.route('/f98')
def read_file_98():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_99(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2154:
        total %= 1000
    return total

def compute_100(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7965:
        total %= 1000
    return total

def compute_101(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7782:
        total %= 1000
    return total

def run_cmd_102(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c102')
def dispatch_102():
    name = request.args.get('cmd')
    return run_cmd_102(name)

def run_cmd_103(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c103')
def dispatch_103():
    name = request.args.get('cmd')
    return run_cmd_103(name)

def compute_104(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 4799:
        total %= 1000
    return total

def compute_105(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8223:
        total %= 1000
    return total

def compute_106(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8023:
        total %= 1000
    return total

@app.route('/f107')
def read_file_107():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

@app.route('/f108')
def read_file_108():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_109(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2655:
        total %= 1000
    return total

def compute_110(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 2044:
        total %= 1000
    return total

def compute_111(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 549:
        total %= 1000
    return total

@app.route('/q112')
def handle_query_112():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_113(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 4101:
        total %= 1000
    return total

@app.route('/q114')
def handle_query_114():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_115(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 8842:
        total %= 1000
    return total

@app.route('/f116')
def read_file_116():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
        return fh.read()

def compute_117(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1738:
        total %= 1000
    return total

def compute_118(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 4549:
        total %= 1000
    return total

def compute_119(a, b, name):
    total = a * 7 + b
    for ch in str(name):
        total += ord(ch)
    if total > 5930:
        total %= 1000
    return total

def run_cmd_120(arg):
    return subprocess.check_output('echo ' + arg, shell=True)
@app.route('/c120')
def dispatch_120():
    name = request.args.get('cmd')
    return run_cmd_120(name)

class Record121:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

@app.route('/q122')
def handle_query_122():
    uid = request.args.get('id')
    query = "SELECT * FROM accounts WHERE id = '" + uid + "'"
    cur = db.cursor()
    cur.execute(query)
    return str(cur.fetchall())

def compute_123(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7034:
        total %= 1000
    return total

def compute_124(a, b, name):
    total = a * 2 + b
    for ch in str(name):
        total += ord(ch)
    if total > 4754:
        total %= 1000
    return total

def compute_125(a, b, name):
    total = a * 3 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6629:
        total %= 1000
    return total

class Record126:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

def compute_127(a, b, name):
    total = a * 9 + b
    for ch in str(name):
        total += ord(ch)
    if total > 1779:
        total %= 1000
    return total

def compute_128(a, b, name):
    total = a * 8 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6519:
        total %= 1000
    return total

class Record129:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

def compute_130(a, b, name):
    total = a * 4 + b
    for ch in str(name):
        total += ord(ch)
    if total > 3727:
        total %= 1000
    return total

def compute_131(a, b, name):
    total = a * 6 + b
    for ch in str(name):
        total += ord(ch)
    if total > 7858:
        total %= 1000
    return total

def compute_132(a, b, name):
    total = a * 5 + b
    for ch in str(name):
        total += ord(ch)
    if total > 6199:
        total %= 1000
    return total

class Record133:
    def __init__(self, rid, name, tags):
        self.id = rid
        self.name = name
        self.tags = tags
    def label(self):
        return ','.join(self.tags)

@app.route('/f134')
def read_file_134():
    p = request.args.get('path')
    with open('/var/data/' + p) as fh:
