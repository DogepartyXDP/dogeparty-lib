#! /usr/bin/python3
import json
import struct
import decimal
import logging
logger = logging.getLogger(__name__)

D = decimal.Decimal
from fractions import Fraction

from dogepartylib.lib import (config, exceptions, util)

"""Burn {} to earn {} during a special period of time.""".format(config.DOGE, config.XDP)

ID = 60

FIRST_BURN_PRECISION_PROBLEMS = {291266312.50000006:291266312, 120264062.50000001:120264062}

def initialise (db):
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS burns(
                      tx_index INTEGER PRIMARY KEY,
                      tx_hash TEXT UNIQUE,
                      block_index INTEGER,
                      source TEXT,
                      burned INTEGER,
                      earned INTEGER,
                      status TEXT,
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      burns_status_idx ON burns (status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      burns_address_idx ON burns (source)
                   ''')

def validate (db, source, destination, quantity, block_index, overburn=False):
    problems = []

    # Check destination address.
    if destination != util.get_value_by_block_index("burn_address", block_index):
        problems.append('wrong destination address')

    if not isinstance(quantity, int):
        problems.append('quantity must be in satoshis')
        return problems

    if quantity < 0: problems.append('negative quantity')

    # Try to make sure that the burned funds won't go to waste.
    if block_index < util.get_value_by_block_index("burn_start") - 1:
        problems.append('too early')
    elif block_index > util.get_value_by_block_index("burn_end"):
        problems.append('too late')

    return problems

def compose (db, source, quantity, overburn=False):
    cursor = db.cursor()
    destination = util.get_value_by_block_index("burn_address")
    problems = validate(db, source, destination, quantity, util.CURRENT_BLOCK_INDEX, overburn=overburn)
    if problems: raise exceptions.ComposeError(problems)

    # Check that a maximum of 1 DOGE total is burned per address.
    burns = list(cursor.execute('''SELECT * FROM burns WHERE (status = ? AND source = ?)''', ('valid', source)))
    already_burned = sum([burn['burned'] for burn in burns])

    if quantity > (1000000 * config.UNIT - already_burned) and not overburn:
        raise exceptions.ComposeError('1000000 {} may be burned per address'.format(config.DOGE))

    cursor.close()
    return (source, [(destination, quantity)], None)

def parse (db, tx, MAINNET_BURNS, message=None):
    burn_parse_cursor = db.cursor()

    #if config.TESTNET or config.REGTEST:
    problems = []
    status = 'valid'

    if status == 'valid':
        problems = validate(db, tx['source'], tx['destination'], tx['doge_amount'], tx['block_index'], overburn=False)
        if problems: status = 'invalid: ' + '; '.join(problems)

        if tx['doge_amount'] != None:
            sent = tx['doge_amount']
        else:
            sent = 0

    if status == 'valid':
        # Calculate quantity of XDP earned. (Maximum 1 DOGE in total, ever.)
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM burns WHERE (status = ? AND source = ?)''', ('valid', tx['source']))
        burns = cursor.fetchall()
        already_burned = sum([burn['burned'] for burn in burns])
        ONE = util.get_value_by_block_index("burn_limit") * config.UNIT
        max_burn = ONE - already_burned
        if sent > max_burn: burned = max_burn   # Exceeded maximum burn; earn what you can.
        else: burned = sent

        total_time = util.get_value_by_block_index("burn_end") - util.get_value_by_block_index("burn_start")
        partial_time = util.get_value_by_block_index("burn_end") - tx['block_index']
        multiplier = util.get_value_by_block_index("burn_multiplier_constant") + (util.get_value_by_block_index("burn_multiplier_product") * Fraction(partial_time, total_time))
        
        if util.get_value_by_block_index("burn_end") == 378842:
            earned = first_burn_earned(burned, multiplier)
        else:
            earned = round(burned * multiplier)

        # Credit source address with earned XDP.
        if earned >= 0:
            util.credit(db, tx['source'], config.XDP, earned, action='burn', event=tx['tx_hash'])           
        else:
            burned = 0
            earned = 0
    else:
        burned = 0
        earned = 0

    tx_index = tx['tx_index']
    tx_hash = tx['tx_hash']
    block_index = tx['block_index']
    source = tx['source']

    #else:
        # Mainnet burns are hard‐coded.

    #    try:
    #        line = MAINNET_BURNS[tx['tx_hash']]
    #    except KeyError:
    #        return

    #    util.credit(db, line['source'], config.XDP, int(line['earned']), action='burn', event=line['tx_hash'])

    #    tx_index = tx['tx_index']
    #    tx_hash = line['tx_hash']
    #    block_index = line['block_index']
    #    source = line['source']
    #    burned = line['burned']
    #    earned = line['earned']
    #    status = 'valid'

    # Add parsed transaction to message-type–specific table.
    # TODO: store sent in table
    bindings = {
        'tx_index': tx_index,
        'tx_hash': tx_hash,
        'block_index': block_index,
        'source': source,
        'burned': burned,
        'earned': earned,
        'status': status,
    }
    if "integer overflow" not in status:
        sql = 'insert into burns values(:tx_index, :tx_hash, :block_index, :source, :burned, :earned, :status)'
        burn_parse_cursor.execute(sql, bindings)
    else:
        logger.warn("Not storing [burn] tx [%s]: %s" % (tx['tx_hash'], status))
        logger.debug("Bindings: %s" % (json.dumps(bindings), ))

    burn_parse_cursor.close()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4

# For some reason, couple of earned values differ from first burn. 
# Trying to resolve them by fixing the precision problem affects the rest.
# So, this is a hard coded fix of those cases until a better solution is found
def first_burn_earned(burned, multiplier):
    earned_without_rounding = burned * multiplier
    
    if earned_without_rounding in FIRST_BURN_PRECISION_PROBLEMS:
        return FIRST_BURN_PRECISION_PROBLEMS[earned_without_rounding]

    return round(earned_without_rounding)
