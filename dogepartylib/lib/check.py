import json
import requests
import logging
logger = logging.getLogger(__name__)
import warnings
import time
import sys

from dogepartylib.lib import config
from dogepartylib.lib import util
from dogepartylib.lib import exceptions
from dogepartylib.lib import backend
from dogepartylib.lib import database

CONSENSUS_HASH_SEED = 'We can only see a short distance ahead, but we can see plenty there that needs to be done.'

CONSENSUS_HASH_VERSION_MAINNET = 2
CHECKPOINTS_MAINNET = {
    config.BLOCK_FIRST_MAINNET: {'ledger_hash': '63f6e31511057c594c20efc386bfe87269b4a3de2a0a0300a6bec4d9a70a3b99', 'txlist_hash': 'c81daa14e65a3362cf9048f7760ca1a2d2ec801e02bf480517af6f08c9491565'},
    336000: {'ledger_hash': '26caefccd1ad29970cb06f73c998f341e1b54aa33173d84085d415a03d37f3d7', 'txlist_hash': '38ac4e07bfa674b1e3a02e4ade252659e6678f18ad62362cb51c60b6848e4b48'},
    337000: {'ledger_hash': '87808317a64a403fe680f665415ec524fbdb1526ef4b757f59847eaf8138c3fe', 'txlist_hash': 'e1748fb9884bb646c91277fda1096890fd1c1cc4813cbe80fc21b0c42774c047'},
    338000: {'ledger_hash': '18a925de496fc5bc1bcb1f8400103538321622c751304d956cee8f4812c6a6a8', 'txlist_hash': 'ee8af1c3708d713ba40522759a372fef5d51be1e2990c1b9f06f3722c5c47cfe'},
    339000: {'ledger_hash': '5f6f0ff5f06380e0c5903c7a911b46b0f5b9abdf65b33bbf47c134d40af6b983', 'txlist_hash': '14aa5c907b14ae30b55763c02f976f9a9e049625778cc3bc588c7810868e1374'},
    340000: {'ledger_hash': '93c0f83ffaf66d10b0ac6781c93a5453d7cd09386595ff453b016228af9bc26c', 'txlist_hash': '6df5310a25701fd95b2ceb30bc85a909227f2f9cabf2c0a17814a6d63f347ee6'},
    341000: {'ledger_hash': 'ac812144419ed187ee9cd90575199fcf0128a22f34777e726642b5d750cd2e61', 'txlist_hash': 'aeca65266d8983876ef616cb66f14e6ec6cd58ed29c7d63a199ea1fe8d52a7c1'},
    342000: {'ledger_hash': '1d3c0987440a70712a4c5d6db037ff63b24809d85823dd61c6a2197790346807', 'txlist_hash': '2e48a2b722bc85c61137173d1d48663e8a85e291d167467a00d4d954b154dd72'},
    343000: {'ledger_hash': '9f0c5705c774268a577dac8d7c45f8f9227fb2a032d68c868821324ac48cbe46', 'txlist_hash': '4f87d971acf9eda2386bb76cefbd50e6c503e1a6c01c657fe38e4d7dc6be461f'},
    344000: {'ledger_hash': 'eed86aead1eb4505c4b6e84583cc8894ee35af88ff8714097e6db48886faacee', 'txlist_hash': 'ab34954487c887c8930035bd8a0f94aa11ddc1f2992fd1c74282794b745b1ea4'},
    345000: {'ledger_hash': '9c52fb6cc426095801ef26f0b4d7efdfbd3c32680465e236c7fa54d236f2c8ad', 'txlist_hash': 'a777e43cc4949d8aacb6fc78854829cf4dda49b5cd239b400a07a9aa47e03b4f'},
    350000: {'ledger_hash': 'b924189cb00e66cb7f449563e09ca9f79f44df124ce8167246a3bc26dc2c3a4c', 'txlist_hash': '44b930467c0cee74d77ddf905ef4f37b52a0ef5ebf2a6dae92427df468634d6b'},
    355000: {'ledger_hash': '939be9c6156731cc8de741aee19a0483f1efac6d340c22934e8c1df1b247229d', 'txlist_hash': '9e757f6d88f2ceee224aab0fdf37aca1e5b66e44f5629b6f667bf8b57af35fcc'},
    360000: {'ledger_hash': 'c090855c9afbd00a486d4d7e7657c0458200934d9f5430c5b3be94087c83ed73', 'txlist_hash': 'f1192262d21f01a631670cd43fe121e49c340db526eb21684104627642cbab61'},
    365000: {'ledger_hash': 'b1141e560863a4fe6e8f1509a8d95742c7827bbc34cd0e623a8843e4bf15af5c', 'txlist_hash': '7edab1b93460d64c7f84f8d83e6144c4d924df4a16739b4fc23b395faa9c441a'},
    366000: {'ledger_hash': '23f18fc7987efa935cfe4fb5e61eec94b8ffdd848c1128e02034c39cd7069f81', 'txlist_hash': 'd58e9f60eebf3afff3e69a3efc9f64348eec36717fc418fe19e5efd74829c8af'},
    370000: {'ledger_hash': '0d01cf2f14a84811b7bdfe1befd6d457d29145fd5000937cc0ec07a0e45bc77b', 'txlist_hash': '2032ab28c6359fe53b17f48753a1fa529ec083b2aa509788fb376e214dcfee52'},
    375000: {'ledger_hash': '61489418b1fdc8a6e52de8d3398f3125814bf2c2901b474f510952b19837d978', 'txlist_hash': '771ac085cf58c50399fcdf5e329a98a636629b28b1a3acd203ce117eec9dd236'},
    380000: {'ledger_hash': '03448c7c7a7f8319dfdb4e2540cc5f375e34bc6cf192aa4950e359332583e304', 'txlist_hash': '3f1e0649e43cdcc7654d8668630125b293728312064a330f2807b8af702dbf34'},
    385000: {'ledger_hash': '2100f089d367b7af6a6f5e3f1874ce54aa88c9de413641eccee2811d4e616797', 'txlist_hash': '465f4c25831637219368ec7d26586c35020a520d9d73bc7ece39c0f725f581be'},
    390000: {'ledger_hash': 'eca59314a9c3994e3f45847148b6780d8e347bbe04645fce911078be034c84b6', 'txlist_hash': '1c0a96060d3e1c3781fd1e0664b312d38b090a08720c38693826394e8613ee87'},
    395000: {'ledger_hash': 'e8e6cff91b5063663673a36f0a29add85785d5bcdc647e136f163950bdf4d215', 'txlist_hash': '9c05801539520e08c0d4bb5aae508b6fe3ab57ac35f3faaa79fa087e2601325d'},
    400000: {'ledger_hash': '03675585db5d712ebe2b8cd8c37477663996bd87dcf58b225c33c7f0d755c0a5', 'txlist_hash': '02269dea1fbbf1f48d5d25f286d3fd22821e2c4c88f63606f2cdc03bc211604c'},
    405000: {'ledger_hash': '655fde6af2cbc3795637b40459c974c294ef13d2a3e891c9f442d965ea8c88ab', 'txlist_hash': '0304c00b37cbf152ee1fe3199f243ab868077a4247d702848ef272a1a54f3c43'},
    410000: {'ledger_hash': 'b5b036b94db99f53c2f294d188e705772a11a75ecfbac8c7ad176ce98b527fa2', 'txlist_hash': 'cd08e50832fac249e0c2fb4975029adba366f0c4cdd6feee09664eef31d4a3c1'},
    415000: {'ledger_hash': 'b40b55bb8b4a5fdb310252e30ea6afbd731f22ad46babf202e3e22222c6c16ea', 'txlist_hash': 'ce37d4dbf46809bbb71f26f5d2676e064b8d205c9c3c532e8680d88957ae3d74'},
    420000: {'ledger_hash': '8e9c2dc115b7b23d8bd134949b624e04ba5d82d9bfde1940ff8237064b709ce7', 'txlist_hash': 'f2259e4cfa134c2bf07278071eab533233c0c26e0be4bffa15636931240204a7'},
}

CONSENSUS_HASH_VERSION_TESTNET = 7
CHECKPOINTS_TESTNET = {
    config.BLOCK_FIRST_TESTNET: {'ledger_hash': '3a6acaf99455b5b9085d2af3eb0e3f68360912a80fb983b66aafde772c928ae8', 'txlist_hash': 'c2332f4ec9fba442ccc61e4657468c1b416b960e5578ed6ddb58566ed250cac8'},
    #169000: {'ledger_hash': 'f645e6877da416b8b91670ac927df686c5ea6fc1158c150ae49d594222ed504c', 'txlist_hash': '3e29bcbf3873326097024cc26e9296f0164f552dd79c2ee7cfc344e6d64fa87d'},
    #172000: {'ledger_hash': '384ca28ac56976bc24a6ab7572b41bc61474e6b87fdee814135701d6a8f5c8a2', 'txlist_hash': '6c05c98418a6daa6de82dd59e000d3f3f5407c5432d4ab7d76047873a38e4d4b'},
    #175000: {'ledger_hash': 'f4015c37eb4f31ac42083fd0389cde4868acb5353d3f3abfe2f3a88aba8cae72', 'txlist_hash': '18f278154e9bc3bbcc39da905ab4ad3023742ab7723b55b0fd1c58c36cd3e9bf'},
    #178000: {'ledger_hash': 'd7f70a927f5aeed38e559ddc0bc4697601477ea43cde928ad228fefc195b02da', 'txlist_hash': '1a60e38664b39e0f501b3e5a60c6fc0bd4ed311b74872922c2dde4cb2267fd3e'},
    #181000: {'ledger_hash': '96637b4400cbe084c2c4f139f59b5bc16770815e96306423aaeb2b2677a9a657', 'txlist_hash': '79d577d8fbba0ad6ae67829dfa5824f758286ccd429d65b7d1d42989134d5b57'},
    #184000: {'ledger_hash': 'cae8fec787bba3d5c968a8f4b6fb22a54c96d5acbeadd0425f6b20c3a8813ea3', 'txlist_hash': '097df9c3079df4d96f59518df72492dfd7a79716462e3a4a30d62a37aec6fc16'},
    #187000: {'ledger_hash': '94abfd9c00c8462c155f64011e71af141b7d524e17de5aeda26b7469fe79b5f0', 'txlist_hash': 'a9fc42b69f80ec69f3f98e8a3cd81f4f946544fd0561a62a0891254c16970a87'},
    #190000: {'ledger_hash': '09eb9f2aa605ce77225362b4b556284acdd9f6d3bc273372dfae4a5be9e9b035', 'txlist_hash': '05af651c1de49d0728834991e50000fbf2286d7928961b71917f682a0f2b7171'},
    #193000: {'ledger_hash': '85f3bca8c88246ddfa1a5ec327e71f0696c182ed2a5fedf3712cd2e87e2661ac', 'txlist_hash': '663b34955116a96501e0c1c27f27d24bad7d45995913367553c5cfe4b8b9d0a9'},
    #196000: {'ledger_hash': 'c143026133af2d83bc49ef205b4623194466ca3e7c79f95da2ad565359ccb5ad', 'txlist_hash': '097b8bca7a243e0b9bdf089f34de15bd2dcd4727fb4e88aae7bfd96302250326'},
    #199000: {'ledger_hash': '82caf720967d0e43a1c49a6c75f255d9056ed1bffe3f96d962478faccdaba8ff', 'txlist_hash': '0d99f42184233426d70102d5ac3c80aaecf804d441a8a0d0ef26038d333ab7a7'},
    #202000: {'ledger_hash': 'bef100ae7d5027a8b3f32416c4f26e1f16b21cee2a986c57be1466a3ba338051', 'txlist_hash': '409ed86e4274b511193d187df92e433c734dcc890bf93496e7a7dee770e7035e'},
    #205000: {'ledger_hash': 'afe5e9c3f3a8c6f19c4f9feaf09df051c28202c6bae64f3563a09ffea9e79a6e', 'txlist_hash': '4f9765158855d24950c7e076615b0ad5b72738d4d579decfd3b93c998edf4fcb'},
    #208000: {'ledger_hash': 'e7c7969a6156facb193b77ef71b5e3fac49c6998e5a94ec3b90292be10ece9cc', 'txlist_hash': '6e511790656d3ffec0c912d697e5d1c2a4e401a1606203c77ab5a5855891bc2c'},
    #211000: {'ledger_hash': '42a7c679e51e5e8d38df26b67673b4850e8e6f72723aa19673b3219fcc02b77b', 'txlist_hash': '885ae1e6c21f5fb3645231aaa6bb6910fc21a0ae0ca5dbe9a4011f3b5295b3e7'},
    #214000: {'ledger_hash': '35b2a2ab4a8bfbc321d4545292887b4ccaea73415c7674f795aefa6e240890eb', 'txlist_hash': '72d5cfe1e729a22da9eacd4d7752c881c43a191904556b65a0fae82b770dcdf3'},
    #217000: {'ledger_hash': 'a5552b4998d2e5a516b9310d6592e7368771c1ad3b6e6330f6bc0baa3db31643', 'txlist_hash': '5a2e9fbd9b52ee32b8e8bfff993ed92dc22510aa7448277a704176cf01e55b04'},
    #220000: {'ledger_hash': '5a5e78b55ac294690229abff7ff8f74f390f3a47dc4d08a0bac40e2e89a5bed2', 'txlist_hash': 'f4fa9838fb38d3e5beffb760fae022dcc59c61c506dd28ac83ee48ba814d04b2'},
    #223000: {'ledger_hash': 'eafca6700b9fd8f3992f8a18316e9ad59480ef74a4e7737793c101878aba8e1a', 'txlist_hash': '03deb626e031f30acd394bf49c35e11a487cb11e55dff5ba9a3f6d04b460c7de'},
    #226000: {'ledger_hash': '8012ebaf4c6638173e88ecd3e7bb2242ab88a9bdf877fc32c42dbcd7d2d3bab1', 'txlist_hash': '896274fdba957961083b07b80634126bc9f0434b67d723ed1fa83157ce5cd9a7'},
    #229000: {'ledger_hash': '76357f917235daa180c904cdf5c44366eef3e33539b7b0ba6a38f89582e82d22', 'txlist_hash': '36ecfd4b07f23176cd6960bc0adef97472c13793e53ac3df0eea0dd2e718a570'},
    #232000: {'ledger_hash': '5924f004bfdc3be449401c764808ebced542d2e06ba30c5984830292d1a926aa', 'txlist_hash': '9ff139dacf4b04293074e962153b972d25fa16d862dae05f7f3acc15e83c4fe8'},
    #235000: {'ledger_hash': 'a3d009bd2e0b838c185b8866233d7b4edaff87e5ec4cc4719578d1a8f9f8fe34', 'txlist_hash': '11dcf3a0ab714f05004a4e6c77fe425eb2a6427e4c98b7032412ab29363ffbb2'},
    #238000: {'ledger_hash': '37244453b4eac67d1dbfc0f60116cac90dab7b814d756653ad3d9a072fbac61a', 'txlist_hash': 'c01ed3113f8fd3a6b54f5cefafd842ebf7c314ce82922e36236414d820c5277a'},
    #241000: {'ledger_hash': 'a83c1cd582604130fd46f1304560caf0f4e3300f3ce7c3a89824b8901f13027f', 'txlist_hash': '67e663b75a80940941b8370ada4985be583edaa7ba454d49db9a864a7bb7979c'},
    #244000: {'ledger_hash': 'f96e6aff578896a4568fb69f72aa0a8b52eb9ebffefca4bd7368790341cd821d', 'txlist_hash': '83e7d31217af274b13889bd8b9f8f61afcd7996c2c8913e9b53b1d575f54b7c1'},
    #247000: {'ledger_hash': '85a23f6fee9ce9c80fa335729312183ff014920bbf297095ac77c4105fb67e17', 'txlist_hash': 'eee762f34a3f82e6332c58e0c256757d97ca308719323af78bf5924f08463e12'},
}

CONSENSUS_HASH_VERSION_REGTEST = 1
CHECKPOINTS_REGTEST = {
    config.BLOCK_FIRST_REGTEST: {'ledger_hash': '33cf0669a0d309d7e6b1bf79494613b69262b58c0ea03c9c221d955eb4c84fe5', 'txlist_hash': '33cf0669a0d309d7e6b1bf79494613b69262b58c0ea03c9c221d955eb4c84fe5'},
}

class ConsensusError(Exception):
    pass

def consensus_hash(db, field, previous_consensus_hash, content):
    cursor = db.cursor()
    block_index = util.CURRENT_BLOCK_INDEX

    # Initialise previous hash on first block.
    if block_index <= config.BLOCK_FIRST:
        assert not previous_consensus_hash
        previous_consensus_hash = util.dhash_string(CONSENSUS_HASH_SEED)

    # Get previous hash.
    if not previous_consensus_hash:
        try:
            previous_consensus_hash = list(cursor.execute('''SELECT * FROM blocks WHERE block_index = ?''', (block_index - 1,)))[0][field]
        except IndexError:
            previous_consensus_hash = None
        if not previous_consensus_hash:
            raise ConsensusError('Empty previous {} for block {}. Please launch a `reparse`.'.format(field, block_index))

    # Calculate current hash.
    if config.TESTNET:
        consensus_hash_version = CONSENSUS_HASH_VERSION_TESTNET
    elif config.REGTEST:
        consensus_hash_version = CONSENSUS_HASH_VERSION_REGTEST
    else:
        consensus_hash_version = CONSENSUS_HASH_VERSION_MAINNET

    calculated_hash = util.dhash_string(previous_consensus_hash + '{}{}'.format(consensus_hash_version, ''.join(content)))

    # Verify hash (if already in database) or save hash (if not).
    # NOTE: do not enforce this for messages_hashes, those are more informational (for now at least)
    found_hash = list(cursor.execute('''SELECT * FROM blocks WHERE block_index = ?''', (block_index,)))[0][field] or None
    if found_hash and field != 'messages_hash':
        # Check against existing value.
        if calculated_hash != found_hash:
            raise ConsensusError('Inconsistent {} for block {} (calculated {}, vs {} in database).'.format(
                field, block_index, calculated_hash, found_hash))
    else:
        # Save new hash.
        cursor.execute('''UPDATE blocks SET {} = ? WHERE block_index = ?'''.format(field), (calculated_hash, block_index))

    # Check against checkpoints.
    if config.TESTNET:
        checkpoints = CHECKPOINTS_TESTNET
    elif config.REGTEST:
        checkpoints = CHECKPOINTS_REGTEST
    else:
        checkpoints = CHECKPOINTS_MAINNET

    if field != 'messages_hash' and block_index in checkpoints and checkpoints[block_index][field] != calculated_hash:
        raise ConsensusError('Incorrect {} hash for block {}.  Calculated {} but expected {}'.format(field, block_index, calculated_hash, checkpoints[block_index][field],))

    return calculated_hash, found_hash

class SanityError(Exception):
    pass

def asset_conservation(db):
    logger.debug('Checking for conservation of assets.')
    supplies = util.supplies(db)
    held = util.held(db)
    for asset in supplies.keys():
        asset_issued = supplies[asset]
        asset_held = held[asset] if asset in held and held[asset] != None else 0
        if asset_issued != asset_held:
            raise SanityError('{} {} issued ≠ {} {} held'.format(util.value_out(db, asset_issued, asset), asset, util.value_out(db, asset_held, asset), asset))
        logger.debug('{} has been conserved ({} {} both issued and held)'.format(asset, util.value_out(db, asset_issued, asset), asset))

class VersionError(Exception):
    pass
class VersionUpdateRequiredError(VersionError):
    pass

def check_change(protocol_change, change_name):

    # Check client version.
    passed = True
    if config.VERSION_MAJOR < protocol_change['minimum_version_major']:
        passed = False
    elif config.VERSION_MAJOR == protocol_change['minimum_version_major']:
        if config.VERSION_MINOR < protocol_change['minimum_version_minor']:
            passed = False
        elif config.VERSION_MINOR == protocol_change['minimum_version_minor']:
            if config.VERSION_REVISION < protocol_change['minimum_version_revision']:
                passed = False

    if not passed:
        explanation = 'Your version of {} is v{}, but, as of block {}, the minimum version is v{}.{}.{}. Reason: ‘{}’. Please upgrade to the latest version and restart the server.'.format(
            config.APP_NAME, config.VERSION_STRING, protocol_change['block_index'], protocol_change['minimum_version_major'], protocol_change['minimum_version_minor'],
            protocol_change['minimum_version_revision'], change_name)
        if util.CURRENT_BLOCK_INDEX >= protocol_change['block_index']:
            raise VersionUpdateRequiredError(explanation)
        else:
            warnings.warn(explanation)

def software_version():
    if config.FORCE:
        return
    logger.debug('Checking version.')

    return #<------ this line has to be removed when the next url exists

    try:
        host = 'https://dogepartyxdp.github.io/dogeparty-lib/dogepartylib/protocol_changes.json'
        response = requests.get(host, headers={'cache-control': 'no-cache'})
        versions = json.loads(response.text)
    except (requests.exceptions.ConnectionError, ConnectionRefusedError, ValueError) as e:
        logger.warning('Unable to check version! ' + str(sys.exc_info()[1]))
        return

    for change_name in versions:
        protocol_change = versions[change_name]
        try:
            check_change(protocol_change, change_name)
        except VersionUpdateRequiredError as e:
            logger.error("Version Update Required", exc_info=sys.exc_info())
            sys.exit(config.EXITCODE_UPDATE_REQUIRED)

    logger.debug('Version check passed.')


class DatabaseVersionError(Exception):
    def __init__(self, message, reparse_block_index):
        super(DatabaseVersionError, self).__init__(message)
        self.reparse_block_index = reparse_block_index

def database_version(db):
    if config.FORCE:
        return
    logger.debug('Checking database version.')

    version_major, version_minor = database.version(db)
    if version_major != config.VERSION_MAJOR:
        # Rollback database if major version has changed.
        raise DatabaseVersionError('Client major version number mismatch ({} ≠ {}).'.format(version_major, config.VERSION_MAJOR), config.BLOCK_FIRST)
    elif version_minor != config.VERSION_MINOR:
        # Reparse all transactions if minor version has changed.
        raise DatabaseVersionError('Client minor version number mismatch ({} ≠ {}).'.format(version_minor, config.VERSION_MINOR), None)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
