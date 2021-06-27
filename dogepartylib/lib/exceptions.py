#! /usr/bin/python3

class DatabaseError(Exception):
    pass

class TransactionError(Exception):
    pass

class ParseTransactionError(Exception):
    pass

class AssetError (Exception):
    pass

class AssetNameError(AssetError):
    pass

class AssetIDError(AssetError):
    pass

class MessageError(Exception):
    pass

class ComposeError(MessageError):
    pass

class UnpackError(MessageError):
    pass

class ValidateError(MessageError):
    pass

class DecodeError(MessageError):
    pass

class PushDataDecodeError(DecodeError):
    pass

class DOGEOnlyError(MessageError):
    def __init__(self, msg, decodedTx=None):
        super(DOGEOnlyError, self).__init__(msg)
        self.decodedTx = decodedTx

class BalanceError(Exception):
    pass

class EncodingError(Exception):
    pass

class OptionsError(Exception):
    pass

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
