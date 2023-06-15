"""
author: (BRITNEY) wanqiang 信安1901
"""
import random
import secrets
from abc import ABCMeta, abstractmethod
import math
import time
import base64
from secrets import randbits


class Algorithm(metaclass=ABCMeta):
    '''Abstract class for public-key cryptography algorithms.'''

    def fastExpMod(self, b, e, m):
        '''Fast exponentiation algorithm, where b represents the base, e represents the exponent, and m represents the large number N
        :param b is the base
        :param e is the exponent
        :param m is the large number N
        '''
        result = 1
        while e:
            if e & 1:
                result = (result * b) % m
            e >>= 1
            b = int(pow(b, 2)) % m
        return result

    def probin(self, w):
        '''Randomly generate a pseudo prime number, w indicates that you want to generate digits
        :param w is the number of digits
        '''
        while True:
            Possible_Prime = randbits(w)
            if Possible_Prime % 2 != 0 and self.Miller_Rabin_Primity_Test(Possible_Prime)[0] == True:
                return Possible_Prime

    def Miller_Rabin_Primity_Test(self, n, t=10):
        '''Millerbine primality test, where n represents a randomly generated integer and t represents a security parameter
        :param n > 3
        :param t is the number of times to test usually t = 10
        '''
        s = 0
        k = n - 1
        while k % 2 == 0:
            k = k // 2
            s += 1

        for num in range(t):
            b = random.randint(2, n - 1)  # Generate random integer b, and b is greater than 2 and less than n-1
            g = math.gcd(b, n)  # calculate the greatest common divisor of b and n
            if g > 1:
                return [False, 0]
            z = pow(b, k, n)
            if z == 1 or z == n - 1:
                continue
            for i in range(s - 1):
                z = pow(z, 2, n)
                if z == n - 1:
                    break
            else:
                return [False, 0]
        return [True, 1 - (
                1 / 4) ** t]  # Returns the probability that a strong quasi prime number and a sum are prime numbers

    def Extended_Euclid(self, x, n):
        '''Extended Euclid algorithm, Algorithm for modulo minus 1: calculates the value of x2 = x^-1 (mod n).
         :param x symbol for e is the public key
         :param n is the modulus number
        '''
        # if b == 0:
        #     return 1, 0, a
        # else:
        #     x, y, q = self.Extended_Euclid(b, a % b)
        #     print(x,y,q)
        #     x, y = y, (x - (a // b) * y)
        #     return x, y, q
        x0 = x
        y0 = n
        x1 = 0
        y1 = 1
        x2 = 1
        y2 = 0
        while n != 0:
            q = x // n
            (x, n) = (n, x % n)
            (x1, x2) = ((x2 - (q * x1)), x1)
            (y1, y2) = ((y2 - (q * y1)), y1)
        if x2 < 0:
            x2 += y0
        if y2 < 0:
            y2 += x0
        return x2

    @abstractmethod
    def encrypt(self, plaintext=None):
        pass

    @abstractmethod
    def decrypt(self, ciphertext=None):
        pass

    # 将加密后的字节序列转换为base64编码
    def to_base64(self, text=None):
        return base64.b64encode(text).decode()

    # 将base64编码的字节序列转换为加密后的字节序列
    def from_base64(self, text=None):
        return base64.b64decode(text.encode())


class RSA(Algorithm):
    '''RSA algorithm'''

    def __init__(self, bitlength=1024):
        self.q = self.probin(bitlength)  # Generate p 1024-bit prime number
        self.p = self.probin(bitlength)  # Generate q 1024-bit prime number
        self.n = self.p * self.q  # Calculate n
        self.e, self.d = self.Generate_public_and_private_keys()  # Generate public and private keys

    @property
    def Get_Value(self):
        return self.q, self.p, self.n, self.e, self.d

    def Generate_public_and_private_keys(self):
        '''Generate public and private keys'''
        phi = (self.p - 1) * (self.q - 1)  # phi is the Euler function of n
        e = random.randint(1, phi)  # 1 < e < phi and e is pubic key
        while math.gcd(e, phi) != 1:
            e = random.randint(1, phi)
        d = self.Extended_Euclid(e, phi)  # d is private key
        return e, d

    def encrypt(self, plaintext=None):
        '''Encrypt plaintext
        :param plaintext is the plaintext and plaintext is less than n
        '''
        m = int.from_bytes(plaintext.encode(), byteorder='big')  # 把明文字符串转换为字节序列，然后转换为整数
        if m > self.n:
            return "The plaintext is too long,please select a larger bitlength or a shorter plaintext!"
        c = pow(m, self.e, self.n)
        # c2 = c1.to_bytes((c1.bit_length() + 7) // 8, byteorder='big')  # 将整数转换为字节序列
        # c = self.to_base64(c2)  # 将加密后的字节序列转换为base64编码
        return c

    def decrypt(self, ciphertext=None):
        '''Decrypt ciphertext
        :param ciphertext is the ciphertext
        '''
        c = ciphertext
        # c1 = self.from_base64(ciphertext)  # 将base64编码的字节序列转换为加密后的字节序列
        # c2 = int.from_bytes(c1, byteorder='big')  # 将加密后的字节序列转换为整数
        p = pow(c, self.d, self.n)
        p = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big').decode()
        return p

    def decrypt_CRT(self, ciphertext=None):
        '''Decrypt ciphertext using Chinese remainder theorem
        :param ciphertext is the ciphertext
        '''
        c = ciphertext
        # c1 = self.from_base64(ciphertext)
        # c2 = int.from_bytes(c1, byteorder='big')
        dp = self.d % (self.p - 1)
        dq = self.d % (self.q - 1)
        inv_p = self.Extended_Euclid(self.p, self.q)
        inv_q = (1 - self.p * inv_p) // self.q
        x1 = pow(pow(c, 1, self.p), dp, self.p)
        x2 = pow(pow(c, 1, self.q), dq, self.q)
        p = (x1 * self.q * inv_q + x2 * self.p * inv_p) % self.n
        p = p.to_bytes((p.bit_length() + 7) // 8, byteorder='big').decode()
        return [p,dp,dq,inv_p,inv_q,x1,x2]


class EIgameal(Algorithm):
    '''Eigamal algorithm'''

    def __init__(self, bitlength=512):
        self.q = self.probin(bitlength)  # Generate p 512-bit prime number
        self.a, self.d, self.e = self.Generate_public_and_private_keys()  # Generate public and private keys

    @property
    def Get_Value(self):
        return self.q, self.a, self.e, self.d

    def Generate_public_and_private_keys(self):
        '''Generate public and private keys
         public key is (q, a, e)
         private key is (d)
        :param is none
        :return a, e, d
        '''
        a = self.Generate_the_OriginalRoot()  # Generate the original root
        d = random.randint(2, self.q - 2)  # Generate a random number d, and d is greater than 2 and less than q-2
        e = pow(a, d, self.q)  # Calculate e
        return a, d, e

    def probin(self, w):
        ''' a specially safe prime number generator
        :param w is the length of the prime number
        '''
        while True:
            p = super().probin(w - 1)
            q = 2 * p + 1
            if self.Miller_Rabin_Primity_Test(q)[0] == True:
                return q

    def Generate_the_OriginalRoot(self):
        '''Generate the original root
        :return the original root
        '''
        q1 = 2
        q2 = (self.q - 1) // 2
        while True:
            g = random.randint(2, self.q - 2)
            if pow(g, (self.q - 1) // q1, self.q) != 1 and pow(g, (self.q - 1) // q2, self.q) != 1:
                break
        return g
        # item = set()
        # n = self.q - 1
        # res = 2
        # while res <= n:
        #       if n % res == 0:
        #           item.add(res)
        #           while n % res == 0:
        #                 n = n // res
        #       res += 1
        # print(item)
        # while True:
        #     a = random.randint(2, self.q - 1)  # Generate a random number a, and a is greater than 2 and less than q-1
        #     flag = True
        #     for key in item:
        #         p = (self.q - 1) // key
        #         if pow(a, p, self.q) == 1:
        #             flag = False
        #             break
        #     if flag == True:
        #         print(f"{a} is the original root")
        #         break

    def to_base64(self, text=None):
        '''Convert text to base64
        text is C1 and C2 convert to base64
        :param text == [C1, C2]
        :return base64_text
        '''
        return base64.b64encode(str(text).encode()).decode()

    def from_base64(self, text=None):
        '''Convert base64 to text
        :param text is to_base64([C1, C2])
        :return [C1, C2]
        '''
        return eval(base64.b64decode(text).decode())

    def encrypt(self, plaintext=None):
        '''Encrypt plaintext
        :param plaintext
        :return C1 and C2
        '''
        m = int.from_bytes(plaintext.encode(), byteorder='big')
        if m > self.q:
            return "The plaintext is too long,please select a larger bitlength or a shorter plaintext!"

        r = random.randint(1, self.q - 1)
        C1 = pow(self.a, r, self.q)
        C2 = (m * pow(self.e, r, self.q)) % self.q
        # print([C1, C2])
        # c = self.to_base64([C1, C2])
        return [C1, C2, r]

    def decrypt(self, C1, C2):
        '''Decrypt ciphertext
        :param C1 is the first ciphertext
        :param C2 is the K*m mod q and K = e^r mod q
        :return plaintext
        '''
        # C = self.from_base64(c)
        C1_reseve = self.Extended_Euclid(C1, self.q)
        m = ((pow(C1_reseve, self.d, self.q) * C2) % self.q)
        plaintext = m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode()
        return plaintext


class ECC(Algorithm):
    ''' ECC algoritm'''

    def __init__(self, CurveName=None, bitlength=20):
        if CurveName == "基本曲线" or CurveName == None:
            self.p = self.probin(bitlength)
            self.a, self.b = self.Generate_a_and_b()
            self.G = self.Generate_G()
            self.k, self.K1 = self.Generate_publickey_and_privatekey()
            self.CurveName = "基本曲线"
        else:
            self.CurveName = CurveName
            self.CurveNameChoice(CurveName)

    # 获取椭圆曲线上的所有的点
    def GetPoints(self):
        points_x = []
        points_y = []
        for x in range(self.p):
            for y in range(self.p):
                if (math.pow(y, 2) - math.pow(x, 3) - self.a * x - self.b) % self.p == 0:
                    points_x.append(x)
                    points_y.append(y)
        return points_x, points_y

    def CurveNameChoice(self, Curvename):  # 选择sepc256k1曲线 密钥长度256位
        if Curvename == 'secp256k1':
            self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
            self.a = 0
            self.b = 7
            self.G = [0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                      0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8]
            self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
            self.k = random.randint(1, self.n - 1)
            self.K1 = self.double_and_add(self.k, self.G[0], self.G[1], self.a, self.p)
            self.h = 1  # 余因子 = 点数/阶数

        elif Curvename == 'sm2p256v1':
            self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
            self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
            self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
            self.G = [0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
                      0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0]
            self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
            self.h = 1
            self.k = random.randint(1, self.n - 1)
            self.K1 = self.double_and_add(self.k, self.G[0], self.G[1], self.a, self.p)

        elif Curvename == 'secp256r1':
            self.p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
            self.a = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
            self.b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
            self.n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
            self.G = [0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                      0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5]
            self.h = 1
            self.k = random.randint(1, self.n - 1)
            self.K1 = self.double_and_add(self.k, self.G[0], self.G[1], self.a, self.p)

        elif Curvename == 'secp384r1':
            self.p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF
            self.a = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
            self.b = 0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
            self.n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
            self.h = 1
            self.G = [
                0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
                0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB73617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F]
            self.k = random.randint(1, self.n - 1)
            self.K1 = self.double_and_add(self.k, self.G[0], self.G[1], self.a, self.p)

        elif Curvename == 'secp521r1':
            self.p = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
            self.a = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
            self.b = 0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00
            self.n = 0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409
            self.h = 1
            self.G = [
                0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66,
                0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650]
            self.k = random.randint(1, self.n - 1)
            self.K1 = self.double_and_add(self.k, self.G[0], self.G[1], self.a, self.p)

    @property
    def Get_Value(self):
        return self.p, self.a, self.b, self.G, self.k, self.K1

    def Generate_publickey_and_privatekey(self):
        '''Generate public key and private key
        :return public key and private key
        '''
        k = self.Generate_k()
        K1 = self.double_and_add(k, self.G[0], self.G[1], self.a, self.p)
        return k, K1

    def Generate_a_and_b(self):
        '''Generate a and b
        :return a and b
        '''
        while True:
            a = random.randint(1, self.p - 1)
            b = random.randint(1, self.p - 1)
            if (4 * pow(a, 3, self.p) + 27 * pow(b, 2, self.p)) % self.p != 0:
                break
        return a, b

    # 随机选择椭圆曲线上的一个点作为生成元
    def Generate_G(self):
        ''' Generate G'''
        while True:
            x = random.randint(1, self.p - 1)
            y2 = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            if math.pow(math.isqrt(y2), 2) == y2:
                y = math.isqrt(y2)
                break
        return [x, y]

    def Generate_k(self):
        '''Generate k
        :return k
        '''
        x, y = self.G[0], self.G[1]
        t = self.Get_Order(x, y, self.a, self.p)
        k = random.randint(2, t - 1)  # 1 < k < |E_p(a, b)|
        return k

    def Point_addition(self, x1, y1, x2, y2, a, p):

        '''Point addition
        :param x1 and y1 is the first point
        :param x2 and y2 is the second point
        :param a is the parameter of the curve
        :param p is the prime number
        :return x3 and y3 is the sum of the two points
        '''

        # x1 = 0 and y1 = 0
        if x1 == 0 and y1 == 0:
            return x2, y2
        # x2 = 0 and y2 = 0
        if x2 == 0 and y2 == 0:
            return x1, y1

        # P == Q
        if x1 == x2 and y1 == y2:
            k = ((3 * pow(x1, 2, p) + a) * self.Extended_Euclid(2 * y1, p)) % p
        # P != Q
        else:
            k = ((y1 - y2) * self.Extended_Euclid(x1 - x2, p)) % p

        x3 = (pow(k, 2, p) - x1 - x2) % p
        y3 = (k * (x1 - x3) - y1) % p
        return x3, y3

    def Get_Order(self, x, y, a, p):

        '''Get the order of the point
        :param x and y is the point
        :param a is the parameter of the curve
        :param p is the prime number
        :return the order of the point
        '''

        x1, y1 = x, y
        x2, y2 = x, ((-y) % p)
        res = 1
        while True:
            x1, y1 = self.Point_addition(x1, y1, x, y, a, p)
            res += 1
            if x1 == x2 and y1 == y2:
                break
        return res

    def Get_Order_FLOYD(self, x, y, a, p):
        """Get the order of the point."""
        x1, y1 = x, y
        x2, y2 = x, (-y) % p
        k = 1
        while (x1, y1) != (x2, y2):
            x1, y1 = self.Point_addition(x1, y1, x, y, a, p)
            x2, y2 = self.Point_addition(x2, y2, x, y, a, p)
            x2, y2 = self.Point_addition(x2, y2, x, y, a, p)
            k += 1
        return k

    def Calculate_kG(self, k, x, y, a, p):

        '''Calculate kG
        :param k is the random number
        :param x and y is the point
        :param a is the parameter of the curve
        :param p is the prime number
        :return kG
        '''

        res = 1
        x1, y1 = x, y
        while True:
            if res == k:
                break
            x1, y1 = self.Point_addition(x1, y1, x, y, a, p)
            res += 1
        return [x1, y1]

    def bits(self, k):
        '''Binary number generator for multiplication addition
        for example bits(97) = 1,0,0,0,0,1,1
        '''
        while k:
            yield k & 1
            k >>= 1

    def double_and_add(self, k, x, y, a, p):
        """
        Returns the result of k * P, It's faster to multiply and add!
        """
        result_x = 0
        result_y = 0
        P_x, P_y = x, y
        for _ in self.bits(k):
            if _ == 1:
                result_x, result_y = self.Point_addition(result_x, result_y, P_x, P_y, a, p)
            P_x, P_y = self.Point_addition(P_x, P_y, P_x, P_y, a, p)
        return [result_x, result_y]

    def Encode(self, plaintext=None):
        '''Encode plaintext
        plaintext will become two plaintext group [m1, m2]
        '''
        plaintext = int.from_bytes(plaintext.encode(), 'big')
        plaintext_bitlength = len(bin(plaintext)) - 2
        P1 = plaintext
        P2_string = ''
        if plaintext_bitlength % 2 != 0:
            move_bit = plaintext_bitlength // 2 + 1
            for x in range(move_bit):
                P2_string = str(P1 & 1) + P2_string
                P1 = P1 >> 1
            m1 = P1
            m2 = int(P2_string, 2)
            m2_length = len(P2_string)
        else:
            move_bit = plaintext_bitlength // 2
            for x in range(move_bit):
                P2_string = str(P1 & 1) + P2_string
                P1 = P1 >> 1
            m1 = P1
            m2 = int(P2_string, 2)
            m2_length = len(P2_string)
        return [m1, m2, m2_length]

    def encrypt(self, m1=None, m2=None):
        '''Encrypt encode plaintext'''
        if m1 > self.p or m2 > self.p:
            return "Error: m1 or m2 is larger than p!"
        self.r = random.randint(1, self.p - 1)
        self.C = self.double_and_add(self.r, self.G[0], self.G[1], self.a, self.p)
        self.Q = self.double_and_add(self.r, self.K1[0], self.K1[1], self.a, self.p)
        c3 = (m1 * self.Q[0]) % self.p
        c4 = (m2 * self.Q[1]) % self.p
        c1 = self.C[0]
        c2 = self.C[1]
        return [c1, c2, c3, c4]

    def decrypt(self, c1=None, c2=None, c3=None, c4=None):
        '''Decrypt  ciphertext'''
        self.Q = self.double_and_add(self.r, self.K1[0], self.K1[1], self.a, self.p)
        m1 = (c3 * self.Extended_Euclid(self.Q[0], self.p)) % self.p
        m2 = (c4 * self.Extended_Euclid(self.Q[1], self.p)) % self.p
        return [m1, m2]

    def Decode(self, m1=None, m2=None, m2_length=None):
        '''Decode plaintext
        :param m1 and m2 is the plaintext
        :param m2_length is the length of m2 in binary
        '''
        m1_string = bin(m1)[2:]
        m2_string = bin(m2)[2:]
        if len(m2_string) < m2_length:
            m2_string = '0' * (m2_length - len(m2_string)) + m2_string
        plainstring = m1_string + m2_string
        plaintext = int(plainstring, 2)
        plaintext = plaintext.to_bytes((plaintext.bit_length() + 7) // 8, 'big').decode()
        return plaintext


class Diffie_Hellman(Algorithm):
    def __init__(self, bitlength=10):
        self.q = self.probin(bitlength)
        self.a = self.Generate_the_OriginalRoot()

    def probin(self, w):
        ''' a specially safe prime number generator
        :param w is the length of the prime number
        '''
        while True:
            p = super().probin(w - 1)
            q = 2 * p + 1
            if self.Miller_Rabin_Primity_Test(q)[0] == True:
                return q

    def Generate_the_OriginalRoot(self):
        '''Generate the original root
        :return the original root
        '''
        q1 = 2
        q2 = (self.q - 1) // 2
        while True:
            g = random.randint(2, self.q - 2)
            if pow(g, (self.q - 1) // q1, self.q) != 1 and pow(g, (self.q - 1) // q2, self.q) != 1:
                break
        return g

    def Alice_Privatekey(self):
        '''Generate Alice's private key'''
        self.x = random.randint(1, self.q - 1)
        return self.x
    def Alice_Publickey(self):
        '''Generate Alice's public key'''
        self.A = pow(self.a, self.x, self.q)
        return self.A

    def Bob_Privatekey(self):
        '''Generate Bob's private key'''
        self.y = random.randint(1, self.q - 1)
        return self.y
    def Bob_Publickey(self):
        '''Generate Bob's public key'''
        self.B = pow(self.a, self.y, self.q)
        return self.B

    def A_shared_key(self):
        '''Generate the Alice shared key'''
        self.K = pow(self.B, self.x, self.q)
        return self.K
    def B_shared_key(self):
        '''Generate the Bob shared key'''
        self.K = pow(self.A, self.y, self.q)
        return self.K
    def encrypt(self, plaintext=None):
        pass
    def decrypt(self, ciphertext=None):
        pass



if __name__ == '__main__':
    sum = 0
    e = ECC(CurveName='secp256k1')
    plaintext = "qwertyuiopasdfghjklzxcvbnm<>?"
    sum1 = 0
    for x in range(100):
        start = time.time()
        m = e.Encode(plaintext)
        ciphertext = e.encrypt(m[0], m[1])
        end = time.time()
        sum1 += end - start
    print("Encryption time: ", sum1 / 100)
    sum2 = 0
    for x in range(100):
        start = time.time()
        m1 = e.decrypt(ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3])
        plaintext = e.Decode(m1[0], m1[1], m[2])
        end = time.time()
        sum2 += end - start
    print("Decryption time: ", sum2 / 100)



