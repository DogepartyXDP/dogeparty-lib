#! /usr/bin/python3
#
# What is a dispenser?
#
# A dispenser is a type of order where the holder address gives out a given amount
# of units of an asset for a given amount of DOGE satoshis received.
# It's a very simple but powerful semantic to allow swaps to operate on-chain.
#

import binascii
import json
import pprint
import struct
import logging
from math import floor
logger = logging.getLogger(__name__)

from dogepartylib.lib import config
from dogepartylib.lib import exceptions
from dogepartylib.lib import util
from dogepartylib.lib import log
from dogepartylib.lib import message_type
from dogepartylib.lib import address

FORMAT = '>QQQQB'
LENGTH = 33
ID = 12
DISPENSE_ID = 13

STATUS_OPEN = 0
STATUS_OPEN_EMPTY_ADDRESS = 1
#STATUS_OPEN_ORACLE_PRICE = 20
#STATUS_OPEN_ORACLE_PRICE_EMPTY_ADDRESS = 21
STATUS_CLOSED = 10

def initialise(db):
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS dispensers(
                      tx_index INTEGER PRIMARY KEY,
                      tx_hash TEXT UNIQUE,
                      block_index INTEGER,
                      source TEXT,
                      asset TEXT,
                      give_quantity INTEGER,
                      escrow_quantity INTEGER,
                      satoshirate INTEGER,
                      status INTEGER,
                      give_remaining INTEGER,
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                   ''')
                      # Disallows invalids: FOREIGN KEY (order_match_id) REFERENCES order_matches(id))
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      dispensers_source_idx ON dispensers (source)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      dispensers_asset_idx ON dispensers (asset)
                   ''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS dispenses(
                      tx_index INTEGER,
                      dispense_index INTEGER,
                      tx_hash TEXT,
                      block_index INTEGER,
                      source TEXT,
                      destination TEXT,
                      asset TEXT,
                      dispense_quantity INTEGER,
                      dispenser_tx_hash TEXT,
                      PRIMARY KEY (tx_index, dispense_index, source, destination),
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                   ''')
    columns = [column['name'] for column in cursor.execute('''PRAGMA table_info(dispenses)''')]
    if 'dispenser_tx_hash' not in columns:
        cursor.execute('ALTER TABLE dispenses ADD COLUMN dispenser_tx_hash TEXT')
    
    columns = [column['name'] for column in cursor.execute('''PRAGMA table_info(dispensers)''')]
    if 'oracle_address' not in columns:
        cursor.execute('ALTER TABLE dispensers ADD COLUMN oracle_address TEXT')

def validate (db, source, asset, give_quantity, escrow_quantity, mainchainrate, status, open_address, block_index, oracle_address):
    problems = []
    order_match = None
    asset_id = None

    if asset == config.DOGE:
        problems.append('cannot dispense %s' % config.DOGE)
        return None, problems

    # resolve subassets
    asset = util.resolve_subasset_longname(db, asset)

    if status == STATUS_OPEN or status == STATUS_OPEN_EMPTY_ADDRESS:
        if give_quantity <= 0:
            problems.append('give_quantity must be positive')
        if mainchainrate <= 0:
            problems.append('mainchainrate must be positive')
        if escrow_quantity < give_quantity:
            problems.append('escrow_quantity must be greater or equal than give_quantity')
    elif not(status == STATUS_CLOSED):
        problems.append('invalid status %i' % status)

    cursor = db.cursor()
    cursor.execute('''SELECT quantity FROM balances \
                      WHERE address = ? and asset = ?''', (source,asset,))
    available = cursor.fetchall()

    if len(available) == 0:
        problems.append('address doesn\'t has the asset %s' % asset)
    elif len(available) >= 1 and available[0]['quantity'] < escrow_quantity:
        problems.append('address doesn\'t has enough balance of %s (%i < %i)' % (asset, available[0]['quantity'], escrow_quantity))
    else:
        if status == STATUS_OPEN_EMPTY_ADDRESS and not(open_address):
            open_address = source
            status = STATUS_OPEN

        query_address = open_address if status == STATUS_OPEN_EMPTY_ADDRESS else source
        cursor.execute('''SELECT * FROM dispensers WHERE source = ? AND asset = ? AND status=?''', (query_address, asset, STATUS_OPEN))
        open_dispensers = cursor.fetchall()
        if status == STATUS_OPEN or status == STATUS_OPEN_EMPTY_ADDRESS:
            if len(open_dispensers) > 0 and open_dispensers[0]['satoshirate'] != mainchainrate:
                problems.append('address has a dispenser already opened for asset %s with a different mainchainrate' % asset)

            if len(open_dispensers) > 0 and open_dispensers[0]['give_quantity'] != give_quantity:
                problems.append('address has a dispenser already opened for asset %s with a different give_quantity' % asset)
        elif status == STATUS_CLOSED:
            if len(open_dispensers) == 0:
                problems.append('address doesnt has an open dispenser for asset %s' % asset)

        if status == STATUS_OPEN_EMPTY_ADDRESS:
            cursor.execute('''SELECT count(*) cnt FROM balances WHERE address = ?''', (query_address,))
            existing_balances = cursor.fetchall()
            if existing_balances[0]['cnt'] > 0:
                problems.append('cannot open on another address if it has any balance history')

        if len(problems) == 0:
            asset_id = util.generate_asset_id(asset, block_index)
            if asset_id == 0:
                problems.append('cannot dispense %s' % asset) # How can we test this on a test vector?

    cursor.close()
        
    if oracle_address is not None and util.enabled('oracle_dispensers', block_index):
        last_price, last_fee, last_label, last_updated = util.get_oracle_last_price(db, oracle_address, block_index)
        
        if last_price is None:
            problems.append('The oracle address %s has not broadcasted any price yet' % oracle_address)
    
    if len(problems) > 0:
        return None, problems
    else:
        return asset_id, None

def compose (db, source, asset, give_quantity, escrow_quantity, mainchainrate, status, open_address=None, oracle_address=None):
    assetid, problems = validate(db, source, asset, give_quantity, escrow_quantity, mainchainrate, status, open_address, util.CURRENT_BLOCK_INDEX, oracle_address)
    if problems: raise exceptions.ComposeError(problems)

    destination = []
    data = message_type.pack(ID)
    data += struct.pack(FORMAT, assetid, give_quantity, escrow_quantity, mainchainrate, status)
    if status == STATUS_OPEN_EMPTY_ADDRESS and open_address:
        data += address.pack(open_address)
    if oracle_address is not None and util.enabled('oracle_dispensers'):
        oracle_fee = calculate_oracle_fee(db, escrow_quantity, give_quantity, mainchainrate, oracle_address, util.CURRENT_BLOCK_INDEX)
        
        if oracle_fee >= config.DEFAULT_REGULAR_DUST_SIZE:
            destination.append((oracle_address,oracle_fee))
        data += address.pack(oracle_address)        
        
    return (source, destination, data)

def calculate_oracle_fee(db, escrow_quantity, give_quantity, mainchainrate, oracle_address, block_index):
    last_price, last_fee, last_fiat_label, last_updated = util.get_oracle_last_price(db, oracle_address, block_index)
    last_fee_multiplier = (last_fee / config.UNIT)
        
    #Format mainchainrate to ######.##
    oracle_mainchainrate = util.satoshirate_to_fiat(mainchainrate)       
    oracle_mainchainrate_doge = oracle_mainchainrate/last_price
        
    #Calculate the total amount earned for dispenser and the fee
    remaining = int(floor(escrow_quantity / give_quantity))
    total_quantity_doge = oracle_mainchainrate_doge * remaining
    oracle_fee_doge = int(total_quantity_doge * last_fee_multiplier *config.UNIT)
    
    return oracle_fee_doge

def parse (db, tx, message):
    cursor = db.cursor()

    # Unpack message.
    try:
        action_address = tx['source']
        oracle_address = None
        assetid, give_quantity, escrow_quantity, mainchainrate, dispenser_status = struct.unpack(FORMAT, message[0:LENGTH])
        read = LENGTH
        if dispenser_status == STATUS_OPEN_EMPTY_ADDRESS:
            action_address = address.unpack(message[LENGTH:LENGTH+21])
            read = LENGTH + 21
        if len(message) > read:
            oracle_address = address.unpack(message[read:read+21])
        asset = util.generate_asset_name(assetid, util.CURRENT_BLOCK_INDEX)
        status = 'valid'
    except (exceptions.UnpackError, struct.error) as e:
        assetid, give_quantity, mainchainrate, asset = None, None, None, None
        status = 'invalid: could not unpack'

    if status == 'valid':
        if util.enabled("dispenser_parsing_validation", util.CURRENT_BLOCK_INDEX):
            asset_id, problems = validate(db, tx['source'], asset, give_quantity, escrow_quantity, mainchainrate, dispenser_status, action_address if dispenser_status == STATUS_OPEN_EMPTY_ADDRESS else None, tx['block_index'], oracle_address)
        else:
            problems = None
            
        if problems:
            status = 'invalid: ' + '; '.join(problems)
        else:   
            if dispenser_status == STATUS_OPEN or dispenser_status == STATUS_OPEN_EMPTY_ADDRESS:
                cursor.execute('SELECT * FROM dispensers WHERE source=:source AND asset=:asset AND status=:status', {
                    'source': action_address,
                    'asset': asset,
                    'status': STATUS_OPEN
                })
                existing = cursor.fetchall()

                if len(existing) == 0:
                    if (oracle_address != None) and util.enabled('oracle_dispensers', tx['block_index']):
                        oracle_fee = calculate_oracle_fee(db, escrow_quantity, give_quantity, mainchainrate, oracle_address, tx['block_index'])
                           
                        if oracle_fee >= config.DEFAULT_REGULAR_DUST_SIZE:   
                            if tx["destination"] != oracle_address or tx["doge_amount"] < oracle_fee:
                                status = 'invalid: insufficient or non-existent oracle fee'
                    
                    if status == 'valid':
                        # Create the new dispenser
                        try:
                            if dispenser_status == STATUS_OPEN_EMPTY_ADDRESS:
                                cursor.execute('SELECT count(*) cnt FROM balances WHERE address=:address AND quantity > 0', {
                                    'address': action_address
                                })
                                counts = cursor.fetchall()[0]

                                if counts['cnt'] == 0:
                                    util.debit(db, tx['source'], asset, escrow_quantity, action='open dispenser empty addr', event=tx['tx_hash'])
                                    util.credit(db, action_address, asset, escrow_quantity, action='open dispenser empty addr', event=tx['tx_hash'])
                                    util.debit(db, action_address, asset, escrow_quantity, action='open dispenser empty addr', event=tx['tx_hash'])
                                else:
                                    status = 'invalid: address not empty'
                            else:
                                util.debit(db, tx['source'], asset, escrow_quantity, action='open dispenser', event=tx['tx_hash'])
                        except util.DebitError as e:
                            status = 'invalid: insufficient funds'

                    if status == 'valid':
                        bindings = {
                            'tx_index': tx['tx_index'],
                            'tx_hash': tx['tx_hash'],
                            'block_index': tx['block_index'],
                            'source': action_address,
                            'asset': asset,
                            'give_quantity': give_quantity,
                            'escrow_quantity': escrow_quantity,
                            'satoshirate': mainchainrate,
                            'status': STATUS_OPEN,
                            'give_remaining': escrow_quantity,
                            'oracle_address': oracle_address
                        }
                        sql = 'insert into dispensers values(:tx_index, :tx_hash, :block_index, :source, :asset, :give_quantity, :escrow_quantity, :satoshirate, :status, :give_remaining, :oracle_address)'
                        cursor.execute(sql, bindings)
                elif len(existing) == 1 and existing[0]['satoshirate'] == mainchainrate and existing[0]['give_quantity'] == give_quantity:
                    if tx["source"]==action_address:
                        if (oracle_address != None) and util.enabled('oracle_dispensers', tx['block_index']):
                            oracle_fee = calculate_oracle_fee(db, escrow_quantity, give_quantity, mainchainrate, oracle_address, tx['block_index']) 
                               
                            if oracle_fee >= config.DEFAULT_REGULAR_DUST_SIZE:   
                                if tx["destination"] != oracle_address or tx["doge_amount"] < oracle_fee:
                                    status = 'invalid: insufficient or non-existent oracle fee'
                        
                        if status == 'valid':
                            # Refill the dispenser by the given amount
                            bindings = {
                                'source': tx['source'],
                                'asset': asset,
                                'prev_status': dispenser_status,
                                'give_remaining': existing[0]['give_remaining'] + escrow_quantity,
                                'status': STATUS_OPEN,
                                'block_index': tx['block_index'],
                                'action':'refill dispenser',
                                'escrow_quantity':escrow_quantity
                            }
                            try:
                                util.debit(db, tx['source'], asset, escrow_quantity, action='refill dispenser', event=tx['tx_hash'])
                                sql = 'UPDATE dispensers SET give_remaining=:give_remaining \
                                    WHERE source=:source AND asset=:asset AND status=:status'
                                cursor.execute(sql, bindings)
                            except (util.DebitError):
                                status = 'insufficient funds'
                    else:
                        status = 'invalid: can only refill dispenser from source'
                else:
                    status = 'can only have one open dispenser per asset per address'
            elif dispenser_status == STATUS_CLOSED:
                cursor.execute('SELECT tx_index, give_remaining FROM dispensers WHERE source=:source AND asset=:asset AND status=:status', {
                    'source': tx['source'],
                    'asset': asset,
                    'status': STATUS_OPEN
                })
                existing = cursor.fetchall()

                if len(existing) == 1:
                    util.credit(db, tx['source'], asset, existing[0]['give_remaining'], action='close dispenser', event=tx['tx_hash'])
                    bindings = {
                        'source': tx['source'],
                        'asset': asset,
                        'status': STATUS_CLOSED,
                        'block_index': tx['block_index'],
                        'tx_index': existing[0]['tx_index']
                    }
                    sql = 'UPDATE dispensers SET give_remaining=0, status=:status WHERE source=:source AND asset=:asset'
                    cursor.execute(sql, bindings)
                else:
                    status = 'dispenser inexistent'
            else:
                status = 'invalid: status must be one of OPEN or CLOSE'

    if status != 'valid':
        logger.warn("Not storing [dispenser] tx [%s]: %s" % (tx['tx_hash'], status))

    cursor.close()

def is_dispensable(db, address, amount):
    cursor = db.cursor()
    cursor.execute('SELECT * FROM dispensers WHERE source=:source AND status=:status', {
        'source': address,    
        'status': STATUS_OPEN
    })
    dispensers = cursor.fetchall()
    cursor.close()
    
    for next_dispenser in dispensers:
        if next_dispenser["oracle_address"] != None:
            last_price, last_fee, last_fiat_label, last_updated = util.get_oracle_last_price(db, next_dispenser['oracle_address'], util.CURRENT_BLOCK_INDEX)
            fiatrate = util.satoshirate_to_fiat(next_dispenser["satoshirate"])
            if amount >= fiatrate/last_price:
                return True
        else:
            if amount >= next_dispenser["satoshirate"]:
                return True
    
    return False

def dispense(db, tx):
    cursor = db.cursor()
    cursor.execute('SELECT * FROM dispensers WHERE source=:source AND status=:status ORDER BY asset', {
        'source': tx['destination'],
        'status': STATUS_OPEN
    })
    dispensers = cursor.fetchall()

    dispense_index = 0
    for dispenser in dispensers:
        satoshirate = dispenser['satoshirate']
        give_quantity = dispenser['give_quantity']

        if satoshirate > 0 and give_quantity > 0:
            if (dispenser['oracle_address'] != None) and util.enabled('oracle_dispensers', tx['block_index']):
                last_price, last_fee, last_fiat_label, last_updated = util.get_oracle_last_price(db, dispenser['oracle_address'], tx['block_index'])
                fiatrate = util.satoshirate_to_fiat(satoshirate)
                must_give = int(floor(((tx['doge_amount'] / config.UNIT) * last_price)/fiatrate))
            else:
                must_give = int(floor(tx['doge_amount'] / satoshirate))
                
            remaining = int(floor(dispenser['give_remaining'] / give_quantity))
            actually_given = min(must_give, remaining) * give_quantity
            give_remaining = dispenser['give_remaining'] - actually_given

            assert give_remaining >= 0

            # Skip dispense if quantity is 0
            if util.enabled('zero_quantity_value_adjustment_1') and actually_given==0:
                continue

            util.credit(db, tx['source'], dispenser['asset'], actually_given, action='dispense', event=tx['tx_hash'])

            dispenser['give_remaining'] = give_remaining
            if give_remaining < dispenser['give_quantity']:
                # close the dispenser
                dispenser['give_remaining'] = 0
                if give_remaining > 0:
                    # return the remaining to the owner
                    util.credit(db, dispenser['source'], dispenser['asset'], give_remaining, action='dispenser close', event=tx['tx_hash'])
                dispenser['status'] = STATUS_CLOSED

            dispenser['block_index'] = tx['block_index']
            dispenser['prev_status'] = STATUS_OPEN
            cursor.execute('UPDATE DISPENSERS SET give_remaining=:give_remaining, status=:status \
                    WHERE source=:source AND asset=:asset AND satoshirate=:satoshirate AND give_quantity=:give_quantity AND status=:prev_status', dispenser)

            bindings = {
                'tx_index': tx['tx_index'],
                'tx_hash': tx['tx_hash'],
                'dispense_index': dispense_index,
                'block_index': tx['block_index'],
                'source': tx['destination'],
                'destination': tx['source'],
                'asset': dispenser['asset'],
                'dispense_quantity': actually_given,
                'dispenser_tx_hash': dispenser['tx_hash']
            }
            sql = 'INSERT INTO dispenses(tx_index, dispense_index, tx_hash, block_index, source, destination, asset, dispense_quantity, dispenser_tx_hash) \
                    VALUES(:tx_index, :dispense_index, :tx_hash, :block_index, :source, :destination, :asset, :dispense_quantity, :dispenser_tx_hash);'
            cursor.execute(sql, bindings)
            dispense_index += 1

    cursor.close()
