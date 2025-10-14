# Parameters secp256k1
#  from http://www.secg.org/sec2-v2.pdf, par 2.4.1
secp256k1_p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # field size
secp256k1_n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # order
secp256k1_b = 7
secp256k1_a = 0
secp256k1_Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 # generator point x
secp256k1_Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 # generator point y

# secp256k1_curve = ecdsa.ellipticcurve.CurveFp(secp256k1_p, secp256k1_a, secp256k1_b)
# secp256k1_generator = ecdsa.ellipticcurve.Point(secp256k1_curve, secp256k1_Gx, secp256k1_Gy, secp256k1_n)
