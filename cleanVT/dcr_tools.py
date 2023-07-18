import hashlib

from .fx64_operands import EFFECT, REG_SIZE

def md5_hash(message):
    if type(message) is not bytes:
        try:
            message = message.encode()
        except Exception as e:
            print(f"error: {e} {type(e)}!\n\nprovided argument: {message} with type: {type(message)}.")
            
    hashed = hashlib.md5(message)

    return hashed.hexdigest()


class STATE:
    NOTSET                  = -1
    MODIFIED_BYTE           = 1
    OVERWRITTEN_BYTE        = 2   
    MODIFIED_LOBYTE         = 1
    OVERWRITTEN_LOBYTE      = 2

    MODIFIED_HIBYTE         = 3
    OVERWRITTEN_HIBYTE      = 4
    MODIFIED_WORD           = 5
    OVERWRITTEN_WORD        = 6
    MODIFIED_DWORD          = 7
    OVERWRITTEN_DWORD       = 8
    MODIFIED_QWORD          = 9
    OVERWRITTEN_QWORD       = 10
    MEM_READ                = 11
    MEM_WRITE               = 12

    UNKNOWN           = 122
    FALSE             = 123
    TRUE              = 124

def get_resulting_state(data_size, explicit_effect):
        result = STATE.NOTSET

        if explicit_effect == EFFECT.MODIFIED:

            if data_size == REG_SIZE.BYTE or data_size == REG_SIZE.LOBYTE:
                result = STATE.MODIFIED_BYTE
            elif data_size == REG_SIZE.HIBYTE:
                result = STATE.MODIFIED_HIBYTE
            elif data_size == REG_SIZE.WORD:
                result = STATE.MODIFIED_WORD
            elif data_size == REG_SIZE.DWORD:
                result = STATE.MODIFIED_DWORD
            elif data_size == REG_SIZE.QWORD:
                result = STATE.MODIFIED_QWORD

        elif explicit_effect == EFFECT.OVERWRITTEN:

            if data_size == REG_SIZE.BYTE or data_size == REG_SIZE.LOBYTE:
                result = STATE.OVERWRITTEN_BYTE
            elif data_size == REG_SIZE.HIBYTE:
                result = STATE.OVERWRITTEN_HIBYTE
            elif data_size == REG_SIZE.WORD:
                result = STATE.OVERWRITTEN_WORD
            elif data_size == REG_SIZE.DWORD:
                result = STATE.OVERWRITTEN_DWORD
            elif data_size == REG_SIZE.QWORD:
                result = STATE.OVERWRITTEN_QWORD
        else:
            print("454444499")
        
        return result