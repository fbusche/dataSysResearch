# This is most similar to main.py
# It's going to be using the helper functions from the other file
# This is also where the command line interface will be
# Api is dealt with here as well (might have another)

# This is most similar to bmbpy.py
# Need to change this so that it doesn't have all the main menu business (only helper functions)

import argparse
import requests
from Crypto.PublicKey import RSA 
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256  
from Crypto.Hash import RIPEMD160
from flask import Flask, flash, request, redirect, url_for, render_template
from flask_apscheduler import APScheduler
from flask_socketio import SocketIO, send, emit
import webview
import sys
import threading
from mnemonic import Mnemonic
import os
import hashlib
import ed25519
from json2html import json2html
import json
import walletHelper
import requests
import glob
from datetime import datetime
from engineio.async_drivers import gevent



API_URL = 'https://api.example.com'


UPLOAD_FOLDER = 'wallets'
ALLOWED_EXTENSIONS = {'dat'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['SECRET_KEY'] = os.urandom(16)

scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

socketio = SocketIO(app)

mnemo = Mnemonic("english")

privkey = None
pubkey = None
address = None
mnemonic = None
txjson_b = None
balance_cache = None
latest_txs_cache = None

# 216.47.152.84:3000 (need to change this)
NODES = ["178.254.42.138", "173.230.139.86"]

@app.route('/')
def login():
    wallets_display = []

    wallets = glob.glob("wallets/*.dat")
    wallets_legacy = glob.glob("wallets/*.json")

    for wallet in wallets:
        b = wallet.replace("wallets\\", "")
        # wallets_display.append("<a href='/loadwallet/{}'>{}</a>".format(b, b))

    for wallet in wallets_legacy:
        b = wallet.replace("wallets\\", "")
        # wallets_display.append("<a href='/loadwallet/{}'>{}</a>".format(b, b))

    # return render_template("login.html", wallets=json2html.convert(wallets_display, escape=False))
    print("Login Successful") #idea is to display menu options instead of page
    main_menu() # redirect
    

@app.route("/loadwallet/<wallet>")
def load_wallet(wallet):
    global privkey, pubkey, address, mnemonic

    try:
        if ".dat" in wallet:
            with open("wallets/" + wallet) as f:
                d = json.load(f)
                mnemonic = d["mnemonic"]
                address = d["address"]
                unlock_wallet() # idea is that I just call next function instead of redirect
                # return redirect(url_for('unlock_wallet'))
        else:
            pass
            # with open("wallets/" + wallet) as f:
            #     d = json.load(f)
            #     print(d["privateKey"][64:])
            #     privkey = ed25519.SigningKey(binascii.unhexlify(d["privateKey"][64:]))
            #     open("my-secret-key.txt", "wb").write(privkey.to_ascii(encoding="hex"))
            #     pubkey = privkey.get_verifying_key()
            #     address = bmbpy.generate_address_from_pubkey(pubkey.to_bytes())
            #
            #     print(pubkey.to_ascii(encoding="hex"))
            #     print(address)
            #
            #     return redirect(url_for('wallet'))
    except Exception as e:
        print("{} : {}".format(type(e), e))
        flash(str("{} : {}".format(type(e), e)))
        login()
        # return redirect(url_for('login'))


@app.route("/newwallet", methods=['POST'])
def new_wallet():
    global privkey, pubkey, address
    if request.form:
        data = request.form["passwd"]
        if not data:
            data = ""

        words = mnemo.generate(strength=256)
        wseed = mnemo.to_seed(words, passphrase=data)
        seed = hashlib.sha256(wseed).digest()

        privkey = ed25519.SigningKey(seed)
        pubkey = privkey.get_verifying_key()
        address = walletHelper.generate_address_from_pubkey(pubkey.to_bytes())

        # wlist = words.split(" ")
        # windexed = []
        # wdict = {}
        # c = 0
        # for i, word in enumerate(wlist):
        #     wdict[i + 1] = word
        #     c += 1
        #     if c % 4 == 0:
        #         windexed.append(wdict)
        #         wdict = {}

        # phrase = json2html.convert(windexed, escape=False)

        # generate new name

        wallets = glob.glob("wallets/*.dat")
        n = 0
        for wallet in wallets:
            wallet = wallet.replace("wallets\wallet", "")
            wallet = wallet.replace(".dat", "")
            try:
                if int(wallet) > n:
                    n = int(wallet)
            except Exception as e:
                continue

        n += 1

        # save wallet.dat

        d = None
        with open("wallets/wallet{}.dat".format(n), "w") as f:
            d = {"mnemonic": words, "address": address}
            f.write(json.dumps(d))

        with open("wallets/wallet{}.dat".format(n), "r") as f:
            rdata = json.load(f)
            if d != rdata:
                flash("wallet.dat verification failed, please try again")
                main_menu() #redirect
                # return redirect(url_for('create_wallet'))

        print("Wallet Successfully created")
        main_menu()
        #return render_template("newwallet.html", phrase=words)


@app.route("/importwallet", methods=['GET', 'POST'])
def import_wallet():
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and allowed_file(file.filename):

                # generate new name

                wallets = glob.glob("wallets/*.dat")
                n = 0
                for wallet in wallets:
                    wallet = wallet.replace("wallets\wallet", "")
                    wallet = wallet.replace(".dat", "")
                    try:
                        if int(wallet) > n:
                            n = int(wallet)
                    except Exception as e:
                        continue

                n += 1
                filename = "wallet{}.dat".format(n)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                login()
                # return redirect(url_for('login'))
            else:
                main_menu()
                # return redirect(request.url)
        except Exception as e:
            print("{} : {}".format(type(e), e))
            flash("{} : {}".format(type(e), e))
    else:
        main_menu()
        # return render_template("importwallet.html")

@app.route("/importmnemonic", methods=['GET', 'POST'])
def import_mnemonic():
    global privkey, pubkey, address
    if request.method == 'POST':
        if request.form:
            m = request.form["mnemonic"]
            passwd = request.form["passwd"]
            if not passwd:
                passwd = ""
            if m:
                try:

                    wseed = mnemo.to_seed(m, passphrase=passwd)
                    seed = hashlib.sha256(wseed).digest()

                    privkey = ed25519.SigningKey(seed)
                    pubkey = privkey.get_verifying_key()
                    address = walletHelper.generate_address_from_pubkey(pubkey.to_bytes())


                    # generate new name

                    wallets = glob.glob("wallets/*.dat")
                    n = 0
                    for wallet in wallets:
                        wallet = wallet.replace("wallets\wallet", "")
                        wallet = wallet.replace(".dat", "")
                        try:
                            if int(wallet) > n:
                                n = int(wallet)
                        except Exception as e:
                            continue

                    n += 1

                    # save wallet.dat

                    d = None
                    with open("wallets/wallet{}.dat".format(n), "w") as f:
                        d = {"mnemonic": m, "address": address}
                        f.write(json.dumps(d))

                    with open("wallets/wallet{}.dat".format(n), "r") as f:
                        rdata = json.load(f)
                        if d != rdata:
                            flash("wallet.dat verification failed, please try again")
                            main_menu()
                            # return redirect(url_for('create_wallet'))
                    login() 
                    # return redirect(url_for('login'))
                except Exception as e:
                    print("{} : {}".format(type(e), e))
                    flash("{} : {}".format(type(e), e))
    else:
        main_menu()
        # return render_template("importmnemonic.html")


@app.route("/unlockwallet", methods=['GET', 'POST'])
def unlock_wallet():
    global privkey, pubkey, address, mnemonic, balance_cache, latest_txs_cache
    if request.method == 'POST':
        if request.form:
            passwd = request.form["passwd"]
            if not passwd:
                passwd = ""
            words = mnemonic
            wseed = mnemo.to_seed(words, passphrase=passwd)
            seed = hashlib.sha256(wseed).digest()

            privkey = ed25519.SigningKey(seed)
            pubkey = privkey.get_verifying_key()
            if address != walletHelper.generate_address_from_pubkey(pubkey.to_bytes()):
                flash("invalid password")
                unlock_wallet() # redirect to try again
                # return redirect(url_for('unlock_wallet'))

            balance_cache = get_balance(address, 1)
            latest_txs_cache = get_latest_txs(address, 1)

            wallet()
            # return redirect(url_for('wallet'))
    else:
        main_menu()
        # return render_template("unlockwallet.html")


@app.route("/wallet")
def wallet():
    global privkey, pubkey, address

    latest_txs = format_latest_txs()

    overview = {"address: ": "<a href='https://explorer.0xf10.com/account/{}' target='_blank'>{}</a>".format(address, address),
                "balance: ": balance_cache if balance_cache else 0}

    if privkey:
        # Need to print out wallet info
        print("Wallet info")
        
        # return render_template("wallet.html", wallet_overview=json2html.convert(overview, escape=False),
                               # txs=json2html.convert(latest_txs, escape=False))

    main_menu()

@app.route("/sendtx", methods=['GET', 'POST'])
def send_tx():
    global txjson_b
    if request.method == 'POST':
        if request.form:
            amount = request.form["amount"]
            fee = int(request.form["fee"])
            recipient = request.form["recipient"]

            txjson = walletHelper.generate_tx_json(address, recipient, round(float(amount) * 10000), round(fee), privkey)

            flash("<p>amount: {} BMB <br> fee: {} leaf <br> to: {}</p>".format(amount, fee, recipient))

            txjson_b = txjson
            confirm_tx() 
            # return redirect("/confirmtx")

    else:
        print("Transaction unsuccessful")
        main_menu() #if didn't work call again
        #return render_template("sendtx.html")


@app.route("/confirmtx")
def confirm_tx():
    # not sure what this is for????
    print("Running confirm_tx()")
    # return render_template("confirmtx.html", confirm='<a href="/submittx"><p>confirm</p></a>')

@app.route("/submittx")
def submit_tx():
    global txjson_b
    try:
        h = walletHelper.generate_tx_hash_from_json(txjson_b)
        r = walletHelper.submit_tx_json(txjson_b, NODES)

        txjson_b = None

        if r:
            flash('success! <a href="https://explorer.0xf10.com/tx/{}" target="_blank">link</a>'.format(h))
        else:
            flash("error!")

        wallet()
        # return redirect(url_for("wallet"))

    except Exception as e:
        txjson_b = None
        print("{} : {}".format(type(e), e))
        flash(str("{} : {}".format(type(e), e)))
        wallet()
        # return redirect(url_for("wallet"))

    main_menu()


def get_balance(address, t):
    try:
        r = requests.get("https://explorer.0xf10.com/api/accounts/balance?address={}".format(address), timeout=t)
        return r.text
    except Exception as e:
        print("{} : {}".format(type(e), e))
        return 0


def get_latest_txs(address, t):
    try:
        r = requests.get("https://explorer.0xf10.com/api/accounts/transactions?address={}".format(address), timeout=t)
        if r.text.startswith('{"error'):
            return None
        return r.json()
    except Exception as e:
        print("{} : {}".format(type(e), e))
        return None


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def format_latest_txs():
    latest_txs = []

    if not latest_txs_cache:
        latest_txs = ""
    else:
        for i, tx in enumerate(latest_txs_cache):

            latest_txs.append({})

            latest_txs[i]["height"] = tx["height"]
            latest_txs[i]["timestamp"] = tx["timestamp"]
            latest_txs[i]["amount"] = tx["amount"]
            latest_txs[i]["fee"] = tx["fee"]

            if tx["recipient"] == address:
                latest_txs[i]["to/from"] = tx["sender"]
            elif tx["sender"] == address:
                latest_txs[i]["to/from"] = tx["recipient"]

            date_time = datetime.fromtimestamp(tx["timestamp"])
            latest_txs[i]["timestamp"] = date_time.strftime("%m/%d/%Y, %H:%M:%S")

    return latest_txs


@scheduler.task('interval', id='sync', seconds=10, misfire_grace_time=60)
def sync():
    with scheduler.app.app_context():
        global balance_cache, latest_txs_cache

        if address:
            balance_cache = get_balance(address, 5)
            latest_txs_cache = get_latest_txs(address, 5)

        print("synced")


@socketio.on('connect')
def first_connect():
    print("connected")

    overview = {"address: ": '<a href="https://explorer.0xf10.com/account/{}" target="_blank">{}</a>'.format(address, address), "balance: ": balance_cache if balance_cache else 0}

    html = json2html.convert(overview, escape=False)

    emit("overview", {"data": html}, namespace="/")


@socketio.on('update_wallet')
def handle_message():
    latest_txs = format_latest_txs()

    overview = {"address: ": '<a href="https://explorer.0xf10.com/account/{}" target="_blank">{}</a>'.format(address, address), "balance: ": balance_cache if balance_cache else 0}

    html = json2html.convert(overview, escape=False)
    emit("overview", {"data": html}, namespace="/")

    html = json2html.convert(latest_txs, escape=False)
    emit("txs", {"data": html}, namespace="/")


def start_server():
    # app.run(host='127.0.0.1', port=52323)
    # input address Raicu gave
    socketio.run(app, host='216.47.152.84', port=3000)


def main_menu():
    print('Main Menu')
    print('1. Send Money')
    print('2. Get Balance')
    print('3. Get Transaction History')
    print('4. Exit')
    choice = input('Enter choice: ')
    return choice


# Need to update
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Wallet CLI')
    subparsers = parser.add_subparsers(dest='command', required=True)

    create_parser = subparsers.add_parser('create', help='Create a new wallet')
    
    login_parser = subparsers.add_parser('login', help='Login to wallet')

    args = parser.parse_args()

    if args.command == 'login':
        private_key = login()
        while True:
            choice = main_menu()
            if choice == '1':
                recipient = input('Recipient address: ')
                amount = float(input('Amount to send: '))
                sender = walletHelper.generate_keypair()[1].export_key().decode()
                walletHelper.send_money(sender, recipient, amount)
                print("Transaction Successful!\nTransaction ID:")
            
            elif choice == "2":
                # Get balance
                print("Your wallet balance is: ", get_balance(), " coins")

            elif choice == "3":
                # Get transaction history
                print("Transaction history", get_latest_txs(address))
            elif choice == "4":
                # Exit
                print("Exit.")
