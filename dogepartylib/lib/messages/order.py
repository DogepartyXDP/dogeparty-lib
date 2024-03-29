#! /usr/bin/python3

# Filled orders may not be re‐opened, so only orders not involving DOGE (and so
# which cannot have expired order matches) may be filled.
import json
import struct
import decimal
D = decimal.Decimal
import logging
logger = logging.getLogger(__name__)

from dogepartylib.lib import config
from dogepartylib.lib import exceptions
from dogepartylib.lib import util
from dogepartylib.lib import backend
from dogepartylib.lib import log
from dogepartylib.lib import message_type

FORMAT = '>QQQQHQ'
LENGTH = 8 + 8 + 8 + 8 + 2 + 8
ID = 10

def initialise(db):
    cursor = db.cursor()

    # Orders
    cursor.execute('''CREATE TABLE IF NOT EXISTS orders(
                      tx_index INTEGER UNIQUE,
                      tx_hash TEXT UNIQUE,
                      block_index INTEGER,
                      source TEXT,
                      give_asset TEXT,
                      give_quantity INTEGER,
                      give_remaining INTEGER,
                      get_asset TEXT,
                      get_quantity INTEGER,
                      get_remaining INTEGER,
                      expiration INTEGER,
                      expire_index INTEGER,
                      fee_required INTEGER,
                      fee_required_remaining INTEGER,
                      fee_provided INTEGER,
                      fee_provided_remaining INTEGER,
                      status TEXT,
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index),
                      PRIMARY KEY (tx_index, tx_hash))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      orders_block_index_idx ON orders (block_index)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      orders_index_hash_idx ON orders (tx_index, tx_hash)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      expire_idx ON orders (expire_index, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      give_status_idx ON orders (give_asset, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      source_give_status_idx ON orders (source, give_asset, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      give_get_status_idx ON orders (get_asset, give_asset, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      orders_source_idx ON orders (source)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      give_asset_idx ON orders (give_asset)
                   ''')

    # Order Matches
    cursor.execute('''CREATE TABLE IF NOT EXISTS order_matches(
                      id TEXT PRIMARY KEY,
                      tx0_index INTEGER,
                      tx0_hash TEXT,
                      tx0_address TEXT,
                      tx1_index INTEGER,
                      tx1_hash TEXT,
                      tx1_address TEXT,
                      forward_asset TEXT,
                      forward_quantity INTEGER,
                      backward_asset TEXT,
                      backward_quantity INTEGER,
                      tx0_block_index INTEGER,
                      tx1_block_index INTEGER,
                      block_index INTEGER,
                      tx0_expiration INTEGER,
                      tx1_expiration INTEGER,
                      match_expire_index INTEGER,
                      fee_paid INTEGER,
                      status TEXT,
                      FOREIGN KEY (tx0_index, tx0_hash, tx0_block_index) REFERENCES transactions(tx_index, tx_hash, block_index),
                      FOREIGN KEY (tx1_index, tx1_hash, tx1_block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      match_expire_idx ON order_matches (status, match_expire_index)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      forward_status_idx ON order_matches (forward_asset, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      backward_status_idx ON order_matches (backward_asset, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      order_matches_id_idx ON order_matches (id)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      tx0_address_idx ON order_matches (tx0_address)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      tx1_address_idx ON order_matches (tx1_address)
                   ''')

    # Order Expirations
    cursor.execute('''CREATE TABLE IF NOT EXISTS order_expirations(
                      order_index INTEGER PRIMARY KEY,
                      order_hash TEXT UNIQUE,
                      source TEXT,
                      block_index INTEGER,
                      FOREIGN KEY (block_index) REFERENCES blocks(block_index),
                      FOREIGN KEY (order_index, order_hash) REFERENCES orders(tx_index, tx_hash))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      order_expirations_block_index_idx ON order_expirations (block_index)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      order_expirations_source_idx ON order_expirations (source)
                   ''')

    # Order Match Expirations
    cursor.execute('''CREATE TABLE IF NOT EXISTS order_match_expirations(
                      order_match_id TEXT PRIMARY KEY,
                      tx0_address TEXT,
                      tx1_address TEXT,
                      block_index INTEGER,
                      FOREIGN KEY (order_match_id) REFERENCES order_matches(id),
                      FOREIGN KEY (block_index) REFERENCES blocks(block_index))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      order_match_expirations_block_index_idx ON order_match_expirations (block_index)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      order_match_expirations_tx0_address_idx ON order_match_expirations (tx0_address)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      order_match_expirations_tx1_address_idx ON order_match_expirations (tx1_address)
                   ''')

def exact_penalty (db, address, block_index, order_match_id):
    # Penalize addresses that don’t make DOGE payments. If an address lets an
    # order match expire, expire sell DOGE orders from that address.
    cursor = db.cursor()

    # Orders.
    bad_orders = list(cursor.execute('''SELECT * FROM orders \
                                        WHERE (source = ? AND give_asset = ? AND status = ?)''',
                                     (address, config.DOGE, 'open')))
    for bad_order in bad_orders:
        cancel_order(db, bad_order, 'expired', block_index)

    if not (block_index >= 314250 or config.TESTNET or config.REGTEST):   # Protocol change.
        # Order matches.
        bad_order_matches = list(cursor.execute('''SELECT * FROM order_matches \
                                                   WHERE ((tx0_address = ? AND forward_asset = ?) OR (tx1_address = ? AND backward_asset = ?)) AND (status = ?)''',
                                         (address, config.DOGE, address, config.DOGE, 'pending')))
        for bad_order_match in bad_order_matches:
            cancel_order_match(db, bad_order_match, 'expired', block_index)

    cursor.close()
    return


def cancel_order (db, order, status, block_index):
    cursor = db.cursor()

    # Update status of order.
    bindings = {
        'status': status,
        'tx_hash': order['tx_hash']
    }
    sql='update orders set status = :status where tx_hash = :tx_hash'
    cursor.execute(sql, bindings)
    log.message(db, block_index, 'update', 'orders', bindings)

    if order['give_asset'] != config.DOGE:    # Can’t credit DOGE.
        util.credit(db, order['source'], order['give_asset'], order['give_remaining'], action='cancel order', event=order['tx_hash'])

    if status == 'expired':
        # Record offer expiration.
        bindings = {
            'order_index': order['tx_index'],
            'order_hash': order['tx_hash'],
            'source': order['source'],
            'block_index': block_index
        }
        sql='insert into order_expirations values(:order_index, :order_hash, :source, :block_index)'
        cursor.execute(sql, bindings)

    cursor.close()

def cancel_order_match (db, order_match, status, block_index):
    '''The only cancelling is an expiration.
    '''

    cursor = db.cursor()

    # Skip order matches just expired as a penalty. (Not very efficient.)
    if not (block_index >= 314250 or config.TESTNET or config.REGTEST):   # Protocol change.
        order_matches = list(cursor.execute('''SELECT * FROM order_matches \
                                               WHERE (id = ? AND status = ?)''',
                                            (order_match['id'], 'expired')))
        if order_matches:
            cursor.close()
            return

    # Update status of order match.
    bindings = {
        'status': status,
        'order_match_id': order_match['id']
    }
    sql='update order_matches set status = :status where id = :order_match_id'
    cursor.execute(sql, bindings)
    log.message(db, block_index, 'update', 'order_matches', bindings)

    order_match_id = util.make_id(order_match['tx0_hash'], order_match['tx1_hash'])

    # If tx0 is dead, credit address directly; if not, replenish give remaining, get remaining, and fee required remaining.
    orders = list(cursor.execute('''SELECT * FROM orders \
                                    WHERE tx_index = ?''',
                                 (order_match['tx0_index'],)))
    assert len(orders) == 1
    tx0_order = orders[0]
    if tx0_order['status'] in ('expired', 'cancelled'):
        tx0_order_status = tx0_order['status']
        if order_match['forward_asset'] != config.DOGE:
            util.credit(db, order_match['tx0_address'],
                        order_match['forward_asset'],
                        order_match['forward_quantity'], action='order {}'.format(tx0_order_status), event=order_match['id'])
    else:
        tx0_give_remaining = tx0_order['give_remaining'] + order_match['forward_quantity']
        tx0_get_remaining = tx0_order['get_remaining'] + order_match['backward_quantity']
        if tx0_order['get_asset'] == config.DOGE and (block_index >= 297000 or config.TESTNET or config.REGTEST):    # Protocol change.
            tx0_fee_required_remaining = tx0_order['fee_required_remaining'] + order_match['fee_paid']
        else:
            tx0_fee_required_remaining = tx0_order['fee_required_remaining']
        tx0_order_status = tx0_order['status']
        
        if (tx0_order_status == 'filled' and util.enabled("reopen_order_when_dogepay_expires_fix", block_index)): #This case could happen if a DOGEpay expires and before the expiration, the order was filled by a correct DOGEpay
            tx0_order_status = 'open' # So, we have to open the order again
        
        bindings = {
            'give_remaining': tx0_give_remaining,
            'get_remaining': tx0_get_remaining,
            'status': tx0_order_status,
            'fee_required_remaining': tx0_fee_required_remaining,
            'tx_hash': order_match['tx0_hash']
        }
        sql='update orders set give_remaining = :give_remaining, get_remaining = :get_remaining, fee_required_remaining = :fee_required_remaining, status = :status where tx_hash = :tx_hash'
        cursor.execute(sql, bindings)
        log.message(db, block_index, 'update', 'orders', bindings)

    # If tx1 is dead, credit address directly; if not, replenish give remaining, get remaining, and fee required remaining.
    orders = list(cursor.execute('''SELECT * FROM orders \
                                    WHERE tx_index = ?''',
                                 (order_match['tx1_index'],)))
    assert len(orders) == 1
    tx1_order = orders[0]
    if tx1_order['status'] in ('expired', 'cancelled'):
        tx1_order_status = tx1_order['status']
        if order_match['backward_asset'] != config.DOGE:
            util.credit(db, order_match['tx1_address'],
                        order_match['backward_asset'],
                        order_match['backward_quantity'], action='order {}'.format(tx1_order_status), event=order_match['id'])
    else:
        tx1_give_remaining = tx1_order['give_remaining'] + order_match['backward_quantity']
        tx1_get_remaining = tx1_order['get_remaining'] + order_match['forward_quantity']
        if tx1_order['get_asset'] == config.DOGE and (block_index >= 297000 or config.TESTNET or config.REGTEST):    # Protocol change.
            tx1_fee_required_remaining = tx1_order['fee_required_remaining'] + order_match['fee_paid']
        else:
            tx1_fee_required_remaining = tx1_order['fee_required_remaining']
        tx1_order_status = tx1_order['status']
        if (tx1_order_status == 'filled' and util.enabled("reopen_order_when_dogepay_expires_fix", block_index)): #This case could happen if a DOGEpay expires and before the expiration, the order was filled by a correct DOGEpay
            tx1_order_status = 'open' # So, we have to open the order again
        
        bindings = {
            'give_remaining': tx1_give_remaining,
            'get_remaining': tx1_get_remaining,
            'status': tx1_order_status,
            'fee_required_remaining': tx1_fee_required_remaining,
            'tx_hash': order_match['tx1_hash']
        }
        sql='update orders set give_remaining = :give_remaining, get_remaining = :get_remaining, fee_required_remaining = :fee_required_remaining, status = :status where tx_hash = :tx_hash'
        cursor.execute(sql, bindings)
        log.message(db, block_index, 'update', 'orders', bindings)

    if block_index < 286500:    # Protocol change.
        # Sanity check: one of the two must have expired.
        tx0_order_time_left = tx0_order['expire_index'] - block_index
        tx1_order_time_left = tx1_order['expire_index'] - block_index
        assert tx0_order_time_left or tx1_order_time_left

    # Penalize tardiness.
    if block_index >= 313900 or config.TESTNET or config.REGTEST:  # Protocol change.
        if tx0_order['status'] == 'expired' and order_match['forward_asset'] == config.DOGE:
            exact_penalty(db, order_match['tx0_address'], block_index, order_match['id'])
        if tx1_order['status'] == 'expired' and order_match['backward_asset'] == config.DOGE:
            exact_penalty(db, order_match['tx1_address'], block_index, order_match['id'])

    # Re‐match.
    if block_index >= 310000 or config.TESTNET or config.REGTEST: # Protocol change.
        if not (block_index >= 315000 or config.TESTNET or config.REGTEST):   # Protocol change.
            cursor.execute('''SELECT * FROM transactions\
                              WHERE tx_hash = ?''', (tx0_order['tx_hash'],))
            match(db, list(cursor)[0], block_index)
            cursor.execute('''SELECT * FROM transactions\
                              WHERE tx_hash = ?''', (tx1_order['tx_hash'],))
            match(db, list(cursor)[0], block_index)

    if status == 'expired':
        # Record order match expiration.
        bindings = {
            'order_match_id': order_match['id'],
            'tx0_address': order_match['tx0_address'],
            'tx1_address': order_match['tx1_address'],
            'block_index': block_index
        }
        sql='insert into order_match_expirations values(:order_match_id, :tx0_address, :tx1_address, :block_index)'
        cursor.execute(sql, bindings)

    cursor.close()


def validate (db, source, give_asset, give_quantity, get_asset, get_quantity, expiration, fee_required, block_index):
    problems = []
    cursor = db.cursor()

    # For SQLite3
    if give_quantity > config.MAX_INT or get_quantity > config.MAX_INT or fee_required > config.MAX_INT or block_index + expiration > config.MAX_INT:
        problems.append('integer overflow')

    if give_asset == config.DOGE and get_asset == config.DOGE:
        problems.append('cannot trade {} for itself'.format(config.DOGE))

    if not isinstance(give_quantity, int):
        problems.append('give_quantity must be in satoshis')
        return problems
    if not isinstance(get_quantity, int):
        problems.append('get_quantity must be in satoshis')
        return problems
    if not isinstance(fee_required, int):
        problems.append('fee_required must be in satoshis')
        return problems
    if not isinstance(expiration, int):
        problems.append('expiration must be expressed as an integer block delta')
        return problems

    if give_quantity <= 0: problems.append('non‐positive give quantity')
    if get_quantity <= 0: problems.append('non‐positive get quantity')
    if fee_required < 0: problems.append('negative fee_required')
    if expiration < 0: problems.append('negative expiration')
    if expiration == 0 and not (block_index >= 317500 or config.TESTNET or config.REGTEST):   # Protocol change.
        problems.append('zero expiration')

    if not give_quantity or not get_quantity:
        problems.append('zero give or zero get')
    cursor.execute('select * from issuances where (status = ? and asset = ?)', ('valid', give_asset))
    if give_asset not in (config.DOGE, config.XDP) and not cursor.fetchall():
        problems.append('no such asset to give ({})'.format(give_asset))
    cursor.execute('select * from issuances where (status = ? and asset = ?)', ('valid', get_asset))
    if get_asset not in (config.DOGE, config.XDP) and not cursor.fetchall():
        problems.append('no such asset to get ({})'.format(get_asset))
    if expiration > config.MAX_EXPIRATION:
        problems.append('expiration overflow')

    cursor.close()
    return problems

def compose (db, source, give_asset, give_quantity, get_asset, get_quantity, expiration, fee_required):
    cursor = db.cursor()

    # resolve subassets
    give_asset = util.resolve_subasset_longname(db, give_asset)
    get_asset = util.resolve_subasset_longname(db, get_asset)

    # Check balance.
    if give_asset != config.DOGE:
        balances = list(cursor.execute('''SELECT * FROM balances WHERE (address = ? AND asset = ?)''', (source, give_asset)))
        if (not balances or balances[0]['quantity'] < give_quantity):
            raise exceptions.ComposeError('insufficient funds')

    problems = validate(db, source, give_asset, give_quantity, get_asset, get_quantity, expiration, fee_required, util.CURRENT_BLOCK_INDEX)
    if problems: raise exceptions.ComposeError(problems)

    give_id = util.get_asset_id(db, give_asset, util.CURRENT_BLOCK_INDEX)
    get_id = util.get_asset_id(db, get_asset, util.CURRENT_BLOCK_INDEX)
    data = message_type.pack(ID)
    data += struct.pack(
       #FORMAT,
       util.get_value_by_block_index("order_serialization_format"),
       give_id,
       give_quantity,
       get_id,
       get_quantity,
       expiration, fee_required)
    cursor.close()
    return (source, [], data)

def parse (db, tx, message):
    order_parse_cursor = db.cursor()

    # Unpack message.
    try:
        if len(message) != util.get_value_by_block_index("order_serialization_length", tx['block_index']):
            raise exceptions.UnpackError
            
        give_id, give_quantity, get_id, get_quantity, expiration, fee_required = struct.unpack(
            #FORMAT,
            util.get_value_by_block_index("order_serialization_format", tx['block_index']),
            message
        )       
        give_asset = util.get_asset_name(db, give_id, tx['block_index'])
        get_asset = util.get_asset_name(db, get_id, tx['block_index'])
        status = 'open'
    except (exceptions.UnpackError, exceptions.AssetNameError, struct.error) as e:
        give_asset, give_quantity, get_asset, get_quantity, expiration, fee_required = 0, 0, 0, 0, 0, 0
        status = 'invalid: could not unpack'

    price = 0
    if status == 'open':
        try:
            price = util.price(get_quantity, give_quantity)
        except ZeroDivisionError:
            price = 0

        # Overorder
        order_parse_cursor.execute('''SELECT * FROM balances \
                                      WHERE (address = ? AND asset = ?)''', (tx['source'], give_asset))
        balances = list(order_parse_cursor)
        if give_asset != config.DOGE:
            if not balances:
                give_quantity = 0
            else:
                balance = balances[0]['quantity']
                if balance < give_quantity:
                    give_quantity = balance
                    get_quantity = int(price * give_quantity)

        problems = validate(db, tx['source'], give_asset, give_quantity, get_asset, get_quantity, expiration, fee_required, tx['block_index'])
        if problems: status = 'invalid: ' + '; '.join(problems)

        if util.enabled('doge_order_minimum'):
            min_doge_quantity = 1 * config.UNIT  # 1 DOGE
            if util.enabled('doge_order_minimum_adjustment_1'):
                min_doge_quantity = 1 * config.UNIT  # 1 DOGE

            if (give_asset == config.DOGE and give_quantity < min_doge_quantity) or (get_asset == config.DOGE and get_quantity < min_doge_quantity):
                if problems:
                    status += '; doge order below minimum'
                else:
                    status = 'invalid: doge order below minimum'

    # Debit give quantity. (Escrow.)
    if status == 'open':
        if give_asset != config.DOGE:  # No need (or way) to debit DOGE.
            util.debit(db, tx['source'], give_asset, give_quantity, action='open order', event=tx['tx_hash'])

    # Add parsed transaction to message-type–specific table.
    bindings = {
        'tx_index': tx['tx_index'],
        'tx_hash': tx['tx_hash'],
        'block_index': tx['block_index'],
        'source': tx['source'],
        'give_asset': give_asset,
        'give_quantity': give_quantity,
        'give_remaining': give_quantity,
        'get_asset': get_asset,
        'get_quantity': get_quantity,
        'get_remaining': get_quantity,
        'expiration': expiration,
        'expire_index': tx['block_index'] + expiration,
        'fee_required': fee_required,
        'fee_required_remaining': fee_required,
        'fee_provided': tx['fee'],
        'fee_provided_remaining': tx['fee'],
        'status': status,
    }
    if "integer overflow" not in status:
        sql = 'insert into orders values(:tx_index, :tx_hash, :block_index, :source, :give_asset, :give_quantity, :give_remaining, :get_asset, :get_quantity, :get_remaining, :expiration, :expire_index, :fee_required, :fee_required_remaining, :fee_provided, :fee_provided_remaining, :status)'
        order_parse_cursor.execute(sql, bindings)
    else:
        logger.warn("Not storing [order] tx [%s]: %s" % (tx['tx_hash'], status))
        logger.debug("Bindings: %s" % (json.dumps(bindings), ))

    # Match.
    if status == 'open' and tx['block_index'] != config.MEMPOOL_BLOCK_INDEX:
        match(db, tx)

    order_parse_cursor.close()

def match (db, tx, block_index=None):

    cursor = db.cursor()

    # Get order in question.
    orders = list(cursor.execute('''SELECT * FROM orders\
                                    WHERE (tx_index = ? AND status = ?)''', (tx['tx_index'], 'open')))
    if not orders:
        cursor.close()
        return
    else:
        assert len(orders) == 1
    tx1 = orders[0]

    cursor.execute('''SELECT * FROM orders \
                      WHERE (give_asset=? AND get_asset=? AND status=? AND tx_hash != ?)''',
                   (tx1['get_asset'], tx1['give_asset'], 'open', tx1['tx_hash']))

    tx1_give_remaining = tx1['give_remaining']
    tx1_get_remaining = tx1['get_remaining']

    order_matches = cursor.fetchall()
    if tx['block_index'] > 284500 or config.TESTNET or config.REGTEST:  # Protocol change.
        order_matches = sorted(order_matches, key=lambda x: x['tx_index'])                              # Sort by tx index second.
        order_matches = sorted(order_matches, key=lambda x: util.price(x['get_quantity'], x['give_quantity']))   # Sort by price first.

    # Get fee remaining.
    tx1_fee_required_remaining = tx1['fee_required_remaining']
    tx1_fee_provided_remaining = tx1['fee_provided_remaining']

    tx1_status = tx1['status']
    for tx0 in order_matches:
        order_match_id = util.make_id(tx0['tx_hash'], tx1['tx_hash'])
        if not block_index:
            block_index = max(tx0['block_index'], tx1['block_index'])
        if tx1_status != 'open': break

        logger.debug('Considering: ' + tx0['tx_hash'])
        tx0_give_remaining = tx0['give_remaining']
        tx0_get_remaining = tx0['get_remaining']

        # Ignore previous matches. (Both directions, just to be sure.)
        cursor.execute('''SELECT * FROM order_matches
                          WHERE id = ? ''', (util.make_id(tx0['tx_hash'], tx1['tx_hash']), ))
        if list(cursor):
            logger.debug('Skipping: previous match')
            continue
        cursor.execute('''SELECT * FROM order_matches
                          WHERE id = ? ''', (util.make_id(tx1['tx_hash'], tx0['tx_hash']), ))
        if list(cursor):
            logger.debug('Skipping: previous match')
            continue

        # Get fee provided remaining.
        tx0_fee_required_remaining = tx0['fee_required_remaining']
        tx0_fee_provided_remaining = tx0['fee_provided_remaining']

        # Make sure that that both orders still have funds remaining (if order involves DOGE, and so cannot be ‘filled’).
        if tx0['give_asset'] == config.DOGE or tx0['get_asset'] == config.DOGE: # Gratuitous
            if tx0_give_remaining <= 0 or tx1_give_remaining <= 0:
                logger.debug('Skipping: negative give quantity remaining')
                continue
            if block_index >= 292000 and block_index <= 310500 and not config.TESTNET or config.REGTEST:  # Protocol changes
                if tx0_get_remaining <= 0 or tx1_get_remaining <= 0:
                    logger.debug('Skipping: negative get quantity remaining')
                    continue

            if block_index >= 294000 or config.TESTNET or config.REGTEST:  # Protocol change.
                if tx0['fee_required_remaining'] < 0:
                    logger.debug('Skipping: negative tx0 fee required remaining')
                    continue
                if tx0['fee_provided_remaining'] < 0:
                    logger.debug('Skipping: negative tx0 fee provided remaining')
                    continue
                if tx1_fee_provided_remaining < 0:
                    logger.debug('Skipping: negative tx1 fee provided remaining')
                    continue
                if tx1_fee_required_remaining < 0:
                    logger.debug('Skipping: negative tx1 fee required remaining')
                    continue

        # If the prices agree, make the trade. The found order sets the price,
        # and they trade as much as they can.
        tx0_price = util.price(tx0['get_quantity'], tx0['give_quantity'])
        tx1_price = util.price(tx1['get_quantity'], tx1['give_quantity'])
        tx1_inverse_price = util.price(tx1['give_quantity'], tx1['get_quantity'])

        # Protocol change.
        if tx['block_index'] < 286000: tx1_inverse_price = util.price(1, tx1_price)

        logger.debug('Tx0 Price: {}; Tx1 Inverse Price: {}'.format(float(tx0_price), float(tx1_inverse_price)))
        if tx0_price > tx1_inverse_price:
            logger.debug('Skipping: price mismatch.')
        else:
            logger.debug('Potential forward quantities: {}, {}'.format(tx0_give_remaining, int(util.price(tx1_give_remaining, tx0_price))))
            forward_quantity = int(min(tx0_give_remaining, int(util.price(tx1_give_remaining, tx0_price))))
            logger.debug('Forward Quantity: {}'.format(forward_quantity))
            backward_quantity = round(forward_quantity * tx0_price)
            logger.debug('Backward Quantity: {}'.format(backward_quantity))

            if not forward_quantity:
                logger.debug('Skipping: zero forward quantity.')
                continue
            if block_index >= 286500 or config.TESTNET or config.REGTEST:    # Protocol change.
                if not backward_quantity:
                    logger.debug('Skipping: zero backward quantity.')
                    continue

            forward_asset, backward_asset = tx1['get_asset'], tx1['give_asset']

            if block_index >= 313900 or config.TESTNET or config.REGTEST: # Protocol change.
                min_doge_quantity = 0.001 * config.UNIT  # 0.001 DOGE
                if (forward_asset == config.DOGE and forward_quantity <= min_doge_quantity) or (backward_asset == config.DOGE and backward_quantity <= min_doge_quantity):
                    logger.debug('Skipping: below minimum {} quantity'.format(config.DOGE))
                    continue

            # Check and update fee remainings.
            fee = 0
            if block_index >= 286500 or config.TESTNET or config.REGTEST: # Protocol change. Deduct fee_required from provided_remaining, etc., if possible (else don’t match).
                if tx1['get_asset'] == config.DOGE:

                    if block_index >= 310500 or config.TESTNET or config.REGTEST:     # Protocol change.
                        fee = int(tx1['fee_required'] * util.price(backward_quantity, tx1['give_quantity']))
                    else:
                        fee = int(tx1['fee_required_remaining'] * util.price(forward_quantity, tx1_get_remaining))

                    logger.debug('Tx0 fee provided remaining: {}; required fee: {}'.format(tx0_fee_provided_remaining / config.UNIT, fee / config.UNIT))
                    if tx0_fee_provided_remaining < fee:
                        logger.debug('Skipping: tx0 fee provided remaining is too low.')
                        continue
                    else:
                        tx0_fee_provided_remaining -= fee
                        if block_index >= 287800 or config.TESTNET or config.REGTEST:  # Protocol change.
                            tx1_fee_required_remaining -= fee

                elif tx1['give_asset'] == config.DOGE:

                    if block_index >= 310500 or config.TESTNET or config.REGTEST:      # Protocol change.
                        fee = int(tx0['fee_required'] * util.price(backward_quantity, tx0['give_quantity']))
                    else:
                        fee = int(tx0['fee_required_remaining'] * util.price(backward_quantity, tx0_get_remaining))

                    logger.debug('Tx1 fee provided remaining: {}; required fee: {}'.format(tx1_fee_provided_remaining / config.UNIT, fee / config.UNIT))
                    if tx1_fee_provided_remaining < fee:
                        logger.debug('Skipping: tx1 fee provided remaining is too low.')
                        continue
                    else:
                        tx1_fee_provided_remaining -= fee
                        if block_index >= 287800 or config.TESTNET or config.REGTEST:  # Protocol change.
                            tx0_fee_required_remaining -= fee

            else:   # Don’t deduct.
                if tx1['get_asset'] == config.DOGE:
                    if tx0_fee_provided_remaining < tx1['fee_required']: continue
                elif tx1['give_asset'] == config.DOGE:
                    if tx1_fee_provided_remaining < tx0['fee_required']: continue

            if config.DOGE in (tx1['give_asset'], tx1['get_asset']):
                status = 'pending'
            else:
                status = 'completed'
                # Credit.
                util.credit(db, tx1['source'], tx1['get_asset'],
                                    forward_quantity, action='order match', event=order_match_id)
                util.credit(db, tx0['source'], tx0['get_asset'],
                                    backward_quantity, action='order match', event=order_match_id)

            # Debit the order, even if it involves giving dogecoins, and so one
            # can't debit the sending account.
            # Get remainings may be negative.
            tx0_give_remaining -= forward_quantity
            tx0_get_remaining -= backward_quantity
            tx1_give_remaining -= backward_quantity
            tx1_get_remaining -= forward_quantity

            # Update give_remaining, get_remaining.
            # tx0
            tx0_status = 'open'
            if tx0_give_remaining <= 0 or (tx0_get_remaining <= 0 and (block_index >= 292000 or config.TESTNET or config.REGTEST)):    # Protocol change
                if tx0['give_asset'] != config.DOGE and tx0['get_asset'] != config.DOGE:
                    # Fill order, and recredit give_remaining.
                    tx0_status = 'filled'
                    util.credit(db, tx0['source'], tx0['give_asset'], tx0_give_remaining, event=tx1['tx_hash'], action='filled')
            bindings = {
                'give_remaining': tx0_give_remaining,
                'get_remaining': tx0_get_remaining,
                'fee_required_remaining': tx0_fee_required_remaining,
                'fee_provided_remaining': tx0_fee_provided_remaining,
                'status': tx0_status,
                'tx_hash': tx0['tx_hash']
            }
            sql='update orders set give_remaining = :give_remaining, get_remaining = :get_remaining, fee_required_remaining = :fee_required_remaining, fee_provided_remaining = :fee_provided_remaining, status = :status where tx_hash = :tx_hash'
            cursor.execute(sql, bindings)
            log.message(db, block_index, 'update', 'orders', bindings)
            # tx1
            if tx1_give_remaining <= 0 or (tx1_get_remaining <= 0 and (block_index >= 292000 or config.TESTNET or config.REGTEST)):    # Protocol change
                if tx1['give_asset'] != config.DOGE and tx1['get_asset'] != config.DOGE:
                    # Fill order, and recredit give_remaining.
                    tx1_status = 'filled'
                    util.credit(db, tx1['source'], tx1['give_asset'], tx1_give_remaining, event=tx0['tx_hash'], action='filled')
            bindings = {
                'give_remaining': tx1_give_remaining,
                'get_remaining': tx1_get_remaining,
                'fee_required_remaining': tx1_fee_required_remaining,
                'fee_provided_remaining': tx1_fee_provided_remaining,
                'status': tx1_status,
                'tx_hash': tx1['tx_hash']
            }
            sql='update orders set give_remaining = :give_remaining, get_remaining = :get_remaining, fee_required_remaining = :fee_required_remaining, fee_provided_remaining = :fee_provided_remaining, status = :status where tx_hash = :tx_hash'
            cursor.execute(sql, bindings)
            log.message(db, block_index, 'update', 'orders', bindings)

            # Calculate when the match will expire.
            match_expire_index = block_index + util.get_value_by_block_index("order_match_expire_time")
			
			# Record order match.
            bindings = {
                'id': util.make_id(tx0['tx_hash'], tx['tx_hash']),
                'tx0_index': tx0['tx_index'],
                'tx0_hash': tx0['tx_hash'],
                'tx0_address': tx0['source'],
                'tx1_index': tx1['tx_index'],
                'tx1_hash': tx1['tx_hash'],
                'tx1_address': tx1['source'],
                'forward_asset': forward_asset,
                'forward_quantity': forward_quantity,
                'backward_asset': backward_asset,
                'backward_quantity': backward_quantity,
                'tx0_block_index': tx0['block_index'],
                'tx1_block_index': tx1['block_index'],
                'block_index': block_index,
                'tx0_expiration': tx0['expiration'],
                'tx1_expiration': tx1['expiration'],
                'match_expire_index': match_expire_index,
                'fee_paid': fee,
                'status': status,
            }
            sql='insert into order_matches values(:id, :tx0_index, :tx0_hash, :tx0_address, :tx1_index, :tx1_hash, :tx1_address, :forward_asset, :forward_quantity, :backward_asset, :backward_quantity, :tx0_block_index, :tx1_block_index, :block_index, :tx0_expiration, :tx1_expiration, :match_expire_index, :fee_paid, :status)'
            cursor.execute(sql, bindings)

            if tx1_status == 'filled':
                break

    cursor.close()
    return

def expire (db, block_index):
    cursor = db.cursor()

    # Expire orders and give refunds for the quantity give_remaining (if non-zero; if not DOGE).
    cursor.execute('''SELECT * FROM orders \
                      WHERE (status = ? AND expire_index < ?)''', ('open', block_index))
    orders = list(cursor)
    for order in orders:
        cancel_order(db, order, 'expired', block_index)

    # Expire order_matches for DOGE with no DOGE.
    cursor.execute('''SELECT * FROM order_matches \
                      WHERE (status = ? and match_expire_index < ?)''', ('pending', block_index))
    order_matches = list(cursor)
    for order_match in order_matches:
        cancel_order_match(db, order_match, 'expired', block_index)

        # Expire doge sell order if match expires
        if util.enabled('doge_sell_expire_on_match_expire'):
            # Check for other pending order matches involving either tx0_hash or tx1_hash
            bindings = {
                'status': 'pending',
                'tx0_hash': order_match['tx0_hash'],
                'tx1_hash': order_match['tx1_hash']
            }
            sql='select * from order_matches where status = :status and ((tx0_hash in (:tx0_hash, :tx1_hash)) or ((tx1_hash in (:tx0_hash, :tx1_hash))))'
            cursor.execute(sql, bindings)
            order_matches_pending = cursor.fetchall()
            # Set DOGE sell order status as expired only if there are no pending order matches
            if len(order_matches_pending) == 0:
                if order_match['backward_asset'] == config.DOGE and order_match['status'] == "expired":
                    cursor.execute('''SELECT * FROM orders \
                                      WHERE tx_hash = ?''', (order_match['tx1_hash'],))
                    cancel_order(db, list(cursor)[0], 'expired', block_index)
                if order_match['forward_asset'] == config.DOGE and order_match['status'] == "expired":
                    cursor.execute('''SELECT * FROM orders \
                                      WHERE tx_hash = ?''', (order_match['tx0_hash'],))
                    cancel_order(db, list(cursor)[0], 'expired', block_index)

    if block_index >= 315000 or config.TESTNET or config.REGTEST: # Protocol change.
        # Re‐match.
        for order_match in order_matches:
            cursor.execute('''SELECT * FROM transactions\
                              WHERE tx_hash = ?''', (order_match['tx0_hash'],))
            match(db, list(cursor)[0], block_index)
            cursor.execute('''SELECT * FROM transactions\
                              WHERE tx_hash = ?''', (order_match['tx1_hash'],))
            match(db, list(cursor)[0], block_index)

    cursor.close()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
