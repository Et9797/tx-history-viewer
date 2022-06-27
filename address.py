"""
Adapted from Pycardano library: https://github.com/cffls/pycardano 
and bech32 Python library
"""

from enum import Enum
from typing import Union, TypeVar


class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""

    BECH32 = 1
    BECH32M = 2


CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2BC830A3


def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None


def bech32_create_checksum(hrp, data, spec):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp, data, spec):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])


def bech32_decode(bech):
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    if (any(ord(x) < 33 or ord(x) > 126 for x in bech)) or (
        bech.lower() != bech and bech.upper() != bech
    ):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 108:
        return (None, None, None)
    if not all(x in CHARSET for x in bech[pos + 1 :]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1 :]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def decode(addr):
    """Decode a segwit address."""
    _, data, _ = bech32_decode(addr)
    decoded = convertbits(data, 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 108:
        return None
    return decoded


def encode(hrp, witprog):
    """Encode a segwit address."""
    ret = bech32_encode(hrp, convertbits(witprog, 8, 5), 0)
    if bech32_decode(ret) == (None, None, None):
        return None
    return ret



VERIFICATION_KEY_HASH_SIZE = 28
T = TypeVar("T", bound="ConstrainedBytes")


class ConstrainedBytes:
    """A wrapped class of bytes with constrained size.

    Args:
        payload (bytes): Hash in bytes.
    """

    __slots__ = "_payload"

    MAX_SIZE = 32
    MIN_SIZE = 0

    def __init__(self, payload: bytes):
        assert self.MIN_SIZE <= len(payload) <= self.MAX_SIZE, (
            f"Invalid byte size: {len(payload)} for class {self.__class__}, "
            f"expected size range: [{self.MIN_SIZE}, {self.MAX_SIZE}]"
        )
        self._payload = payload

    def __bytes__(self):
        return self.payload

    def __hash__(self):
        return hash(self.payload)

    @property
    def payload(self) -> bytes:
        return self._payload

    def to_primitive(self) -> bytes:
        return self.payload

    @classmethod
    def from_primitive(cls: T, value: Union[bytes, str]) -> T:
        if isinstance(value, str):
            value = bytes.fromhex(value)
        return cls(value)

    def __eq__(self, other):
        if isinstance(other, ConstrainedBytes):
            return self.payload == other.payload
        else:
            return False

    def __repr__(self):
        return f"{self.__class__.__name__}(hex='{self.payload.hex()}')"

    def __str__(self):
        return self.payload.hex()


class VerificationKeyHash(ConstrainedBytes):
    """Hash of a Cardano verification key."""

    MAX_SIZE = MIN_SIZE = VERIFICATION_KEY_HASH_SIZE

    
class AddressType(Enum):
    """
    Address type definition.
    """

    BYRON = 0b1000
    """Byron address"""

    KEY_KEY = 0b0000
    """Payment key hash + Stake key hash"""

    SCRIPT_KEY = 0b0001
    """Script hash + Stake key hash"""

    KEY_SCRIPT = 0b0010
    """Payment key hash + Script hash"""

    SCRIPT_SCRIPT = 0b0011
    """Script hash + Script hash"""

    KEY_POINTER = 0b0100
    """Payment key hash + Pointer address"""

    SCRIPT_POINTER = 0b0101
    """Script hash + Pointer address"""

    KEY_NONE = 0b0110
    """Payment key hash only"""

    SCRIPT_NONE = 0b0111
    """Script hash for payment part only"""

    NONE_KEY = 0b1110
    """Stake key hash for stake part only"""

    NONE_SCRIPT = 0b1111
    """Script hash for stake part only"""


class Network(Enum):
    """
    Network ID
    """

    TESTNET = 0
    MAINNET = 1


class Address:
    """A shelley address. It consists of two parts: payment part and staking part.
        Either of the parts could be None, but they cannot be None at the same time.

    Args:
        payment_part (Union[VerificationKeyHash, ScriptHash, None]): Payment part of the address.
        staking_part (Union[KeyHash, ScriptHash, PointerAddress, None]): Staking part of the address.
        network (Network): Type of network the address belongs to.
    """

    def __init__(
        self,
        payment_part: VerificationKeyHash | None = None,
        staking_part: VerificationKeyHash | None = None,
        network: Network = Network.MAINNET,
    ):
        self._payment_part = payment_part
        self._staking_part = staking_part
        self._network = network
        self._address_type = self._infer_address_type()
        self._header_byte = self._compute_header_byte()
        self._hrp = self._compute_hrp()

    def _infer_address_type(self):
        """Guess address type from the combination of payment part and staking part."""
        payment_type = type(self.payment_part)
        staking_type = type(self.staking_part)
        if payment_type == VerificationKeyHash:
            if staking_type == VerificationKeyHash:
                return AddressType.KEY_KEY
            elif self.staking_part is None:
                return AddressType.KEY_NONE

    @property
    def payment_part(self) -> Union[VerificationKeyHash, None]:
        """Payment part of the address."""
        return self._payment_part

    @property
    def staking_part(
        self,
    ) -> Union[VerificationKeyHash, None]:
        """Staking part of the address."""
        return self._staking_part

    @property
    def network(self) -> Network:
        """Network this address belongs to."""
        return self._network

    @property
    def address_type(self) -> AddressType:
        """Address type."""
        return self._address_type

    @property
    def header_byte(self) -> bytes:
        """Header byte that identifies the type of address."""
        return self._header_byte

    @property
    def hrp(self) -> str:
        """Human-readable prefix for bech32 encoder."""
        return self._hrp

    def _compute_header_byte(self) -> bytes:
        """Compute the header byte."""
        return (self.address_type.value << 4 | self.network.value).to_bytes(
            1, byteorder="big"
        )

    def _compute_hrp(self) -> str:
        """Compute human-readable prefix for bech32 encoder.

        Based on
        `miscellaneous section <https://github.com/cardano-foundation/CIPs/tree/master/CIP-0005#miscellaneous>`_
        in CIP-5.
        """
        prefix = (
            "stake"
            if self.address_type in (AddressType.NONE_KEY, AddressType.NONE_SCRIPT)
            else "addr"
        )
        suffix = "" if self.network == Network.MAINNET else "_test"
        return prefix + suffix

    def __bytes__(self):
        payment = self.payment_part or bytes()
        if self.staking_part is None:
            staking = bytes()
        else:
            staking = self.staking_part
        return self.header_byte + bytes(payment) + bytes(staking)

    def encode(self) -> str:
        """Encode the address in Bech32 format.

        More info about Bech32 `here <https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#Bech32>`_.

        Returns:
            str: Encoded address in Bech32.

        Examples:
            >>> payment_hash = VerificationKeyHash(
            ...     bytes.fromhex("cc30497f4ff962f4c1dca54cceefe39f86f1d7179668009f8eb71e59"))
            >>> print(Address(payment_hash).encode())
            addr1v8xrqjtlfluk9axpmjj5enh0uw0cduwhz7txsqyl36m3ukgqdsn8w
        """
        return encode(self.hrp, bytes(self))

    @classmethod
    def decode(cls, data: str):
        """Decode a bech32 string into an address object.

        Args:
            data (str): Bech32-encoded string.

        Returns:
            Address: Decoded address.

        Raises:
            DecodingException: When the input string is not a valid Shelley address.

        Examples:
            >>> addr = Address.decode("addr1v8xrqjtlfluk9axpmjj5enh0uw0cduwhz7txsqyl36m3ukgqdsn8w")
            >>> khash = VerificationKeyHash(bytes.fromhex("cc30497f4ff962f4c1dca54cceefe39f86f1d7179668009f8eb71e59"))
            >>> assert addr == Address(khash)
        """
        return cls.from_primitive(data)

    def to_primitive(self) -> bytes:
        return bytes(self)

    @classmethod
    def from_primitive(cls, value: Union[bytes, str]):
        if isinstance(value, str):
            value = bytes(decode(value))
        header = value[0]
        payload = value[1:]
        addr_type = AddressType((header & 0xF0) >> 4)
        network = Network(header & 0x0F)
        if addr_type == AddressType.KEY_KEY:
            return cls(
                VerificationKeyHash(payload[:VERIFICATION_KEY_HASH_SIZE]),
                VerificationKeyHash(payload[VERIFICATION_KEY_HASH_SIZE:]),
                network,
            )
        elif addr_type == AddressType.KEY_NONE:
            return cls(VerificationKeyHash(payload), None, network)

    def __repr__(self):
        return f"{self.encode()}"