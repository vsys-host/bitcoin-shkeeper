from app.lib.networks import *
from decimal import Decimal
from app.lib.config.config import NETWORK_DENOMINATORS

def value_to_satoshi(value, network=None):
    if isinstance(value, str):
        if network:
            value = Value(value, network=network)
        else:
            value = Value(value)
    if isinstance(value, Value):
        if network and value.network != network:
            raise ValueError("Value uses different network (%s) then supplied network: %s" % (value.network.name, network))
        value = value.value_sat
    return value

def decimal_value_to_satoshi(value, network=DEFAULT_NETWORK):
    if isinstance(value, Value):
        # Без проверки сети
        return value.value_sat

    if isinstance(value, str):
        value = Decimal(value)
    elif isinstance(value, float):
        value = Decimal(str(value))

    if not isinstance(value, Decimal):
        raise TypeError(f"value must be Decimal, str, float or Value, got {type(value)}")

    return Value(value, network=network).value_sat

class Value:
    @classmethod
    def from_satoshi(cls, value, denominator=None, network=DEFAULT_NETWORK):
        if not isinstance(network, Network):
            network = Network(network)
        if denominator is None:
            denominator = network.denominator
        else:
            if isinstance(denominator, str):
                dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator]
                if dens:
                    denominator = dens[0]
            value = value * (network.denominator / denominator)
        return cls(value or 0, denominator, network)

    def __init__(self, value, denominator=None, network=DEFAULT_NETWORK):
        self.network = network
        if not isinstance(network, Network):
            self.network = Network(network)
        if isinstance(denominator, str):
            dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator]
            if dens:
                denominator = dens[0]
        den_arg = denominator

        if isinstance(value, str):
            value_items = value.split()
            value = value_items[0]
            cur_code = self.network.currency_code
            den_input = 1
            if len(value_items) > 1:
                cur_code = value_items[1]
            network_names = [n for n in NETWORK_DEFINITIONS if
                             NETWORK_DEFINITIONS[n]['currency_code'].upper() == cur_code.upper()]
            if network_names:
                self.network = Network(network_names[0])
                self.currency = cur_code
            else:
                for den, symb in NETWORK_DENOMINATORS.items():
                    if len(symb) and cur_code[:len(symb)] == symb:
                        cur_code = cur_code[len(symb):]
                        network_names = [n for n in NETWORK_DEFINITIONS if
                                         NETWORK_DEFINITIONS[n]['currency_code'].upper() == cur_code.upper()]
                        if network_names:
                            self.network = Network(network_names[0])
                            self.currency = cur_code
                        elif len(cur_code):
                            raise ValueError("Currency symbol not recognised")
                        den_input = den
                        break
            self.value = float(value) * den_input
            self.denominator = den_input if den_arg is None else den_arg
        else:
            self.denominator = den_arg or 1.0
            self.value = float(value) * self.denominator

    def __str__(self):
        return self.str()

    def __repr__(self):
        return "Value(value=%.14f, denominator=%.8f, network='%s')" % \
               (self.value, self.denominator, self.network.name)

    def __int__(self):
        return int(self.value)

    def __float__(self):
        if self.value > self.network.denominator:
            return round(self.value, -int(math.log10(self.network.denominator)))
        else:
            return self.value

    def __lt__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value < other.value

    def __le__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value <= other.value

    def __eq__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot compare values from different networks")
            return self.value == other.value
        else:
            other = Value(other)
            return self.value == other.value and self.network == other.network

    def __ne__(self, other):
        return not self.__eq__(other)

    def __ge__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value >= other.value

    def __gt__(self, other):
        if self.network != other.network:
            raise ValueError("Cannot compare values from different networks")
        return self.value > other.value

    def __add__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value + other) / self.denominator, self.denominator, self.network)

    def __iadd__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value + other) / self.denominator, self.denominator, self.network)

    def __isub__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value - other) / self.denominator, self.denominator, self.network)

    def __sub__(self, other):
        if isinstance(other, Value):
            if self.network != other.network:
                raise ValueError("Cannot calculate with values from different networks")
            other = other.value
        return Value((self.value - other) / self.denominator, self.denominator, self.network)

    def __mul__(self, other):
        return Value((self.value * other) / self.denominator, self.denominator, self.network)

    def __truediv__(self, other):
        return Value((self.value / other) / self.denominator, self.denominator, self.network)

    def __floordiv__(self, other):
        return Value(((self.value / self.denominator) // other), self.denominator, self.network)

    def __round__(self, n=0):
        val = round(self.value / self.denominator, n) * self.denominator
        return Value(val, self.denominator, self.network)

    def __index__(self):
        return self.value_sat

    def str(self, denominator=None, decimals=None, currency_repr='code'):
        if denominator is None:
            denominator = self.denominator
        elif denominator == 'auto':
            # First try denominator=1 and smallest denominator (satoshi)
            if 0.001 <= self.value < 1000:
                denominator = 1
            elif 1 <= self.value / self.network.denominator < 1000:
                denominator = self.network.denominator
            else:  # Try other frequently used denominators
                for den, symb in NETWORK_DENOMINATORS.items():
                    if symb in ['n', 'fin', 'da', 'c', 'd', 'h']:
                        continue
                    if 1 <= self.value / den < 1000:
                        denominator = den
        elif isinstance(denominator, str):
            dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator[:len(symb)] and len(symb)]
            if len(dens) > 1:
                dens = [den for den, symb in NETWORK_DENOMINATORS.items() if symb == denominator]
            if dens:
                denominator = dens[0]
        if denominator in NETWORK_DENOMINATORS:
            den_symb = NETWORK_DENOMINATORS[denominator]
        else:
            raise ValueError("Denominator not found in NETWORK_DENOMINATORS definition")

        if decimals is None:
            decimals = -int(math.log10(self.network.denominator / denominator))
            if decimals > 8:
                decimals = 8
        if decimals < 0:
            decimals = 0
        balance = round(self.value / denominator, decimals)
        cur_code = self.network.currency_code
        if currency_repr == 'symbol':
            cur_code = self.network.currency_symbol
        if currency_repr == 'name':
            cur_code = self.network.currency_name_plural
        if 'sat' in den_symb and self.network.name == 'bitcoin':
            cur_code = ''
        return ("%%.%df %%s%%s" % decimals) % (balance, den_symb, cur_code)

    def str_unit(self, decimals=None, currency_repr='code'):
        return self.str(1, decimals, currency_repr)

    def str_auto(self, decimals=None, currency_repr='code'):
        return self.str('auto', decimals, currency_repr)

    @property
    def value_sat(self):
        return round(self.value / self.network.denominator)

    def to_bytes(self, length=8, byteorder='little'):
        return self.value_sat.to_bytes(length, byteorder)

    def to_hex(self, length=16, byteorder='little'):
        return self.value_sat.to_bytes(length // 2, byteorder).hex()
