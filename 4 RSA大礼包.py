from math import *
import gmpy2
import libnum
import os
from functools import reduce 
from Crypto.Util.number import long_to_bytes
from decimal import Decimal, getcontext
from gmpy2 import gcd, powmod

print("=" * 60)
print("RSA多帧解密分析")
print("=" * 60)

# 初始化变量
text = []
N = []
e = []
c = []
gcdx = []

# 读取文件
print("\n1. 读取Frame文件...")
folder_path = r"C:\Users\惠丹婷\.vscode\4"
for i in range(0, 21):
    x = os.path.join(folder_path, f"Frame{i}")
    with open(x, 'r') as w:
        text.append(w.read())
    tl = len(text[i]) // 3
    N.append(text[i][0:tl])
    e.append(text[i][tl:2*tl])
    c.append(text[i][2*tl:])

# 转换为整数
Nint = [int(i, 16) for i in N]
eint = [int(i, 16) for i in e]
cint = [int(i, 16) for i in c]

print(f"成功读取 {len(Nint)} 个Frame")
print(f"公钥指数e: {eint}")

# 寻找共享模数
print("\n2. 检测共享模数攻击...")
for i in range(0, 21):
    for j in range(i+1, 21):
        gcd_val = gcd(Nint[i], Nint[j])
        gcdx.append(gcd_val)
        if gcd_val != 1:
            print(f"发现共享模数: Frame[{i}] 和 Frame[{j}]")

# 快速模幂运算
def fast_m_e(a, b, n):
    result = 1
    a = a % n  
    while b > 0:
        if b & 1:
            result = (result * a) % n
        a = (a * a) % n
        b >>= 1  
    return result

# 共模攻击
def rsa_gong_N_def(e1, e2, c1, c2, n):  
    e1, e2, c1, c2, n = int(e1), int(e2), int(c1), int(c2), int(n)
    s = gmpy2.gcdext(e1, e2)
    s1 = s[1]
    s2 = s[2]
    if s1 < 0:
        s1 = -s1
        c1 = gmpy2.invert(c1, n)
    elif s2 < 0:
        s2 = -s2
        c2 = gmpy2.invert(c2, n)
    m = (fast_m_e(c1, s1, n) * fast_m_e(c2, s2, n)) % n
    return int(m)

print("\n3. 执行共模攻击 (Frame0和Frame4)...")
mtest = rsa_gong_N_def(eint[0], eint[4], cint[0], cint[4], Nint[0])
plaintext = libnum.n2s(mtest)
print(f"解密结果: {plaintext}")

# 初始化明文数组
m = [0] * 20
mx = [0] * 21
m[0] = "My secre"
mx[0] = mx[4] = "My secre"

print("\n4. 分解共享模数 (Frame1和Frame18)...")
p18 = gcd(Nint[1], Nint[18])
q1 = Nint[1] // p18
q18 = Nint[18] // p18
fy1 = (p18-1) * (q1-1)
fy18 = (p18-1) * (q18-1)
d1 = gmpy2.invert(eint[1], fy1)
d18 = gmpy2.invert(eint[18], fy18)
m1 = fast_m_e(cint[1], d1, Nint[1])
m18 = fast_m_e(cint[18], d18, Nint[18])
print(f"Frame1解密: {libnum.n2s(m1)}")
print(f"Frame18解密: {libnum.n2s(m18)}")

m[10] = "m A to B"
m[11] = ". Imagin"
mx[18] = "m A to B"
mx[1] = ". Imagin"

# 中国剩余定理攻击
print("\n5. 低指数攻击 (e=5)...")
n2 = [Nint[3], Nint[8], Nint[12], Nint[16], Nint[20]]
c2 = [cint[3], cint[8], cint[12], cint[16], cint[20]]
e2 = [eint[3], eint[8], eint[12], eint[16], eint[20]]

def ext_gcd(a, b): 
    if b == 0:          
        return 1, 0, a     
    else:         
        x, y, gcd_val = ext_gcd(b, a % b)   
        x, y = y, (x - (a // b) * y)         
        return x, y, gcd_val

def shengyu5(a1, a2, a3, a4, a5, m1, m2, m3, m4, m5):
    if gcd(m1, m2) == 1 and gcd(m1, m3) == 1 and gcd(m2, m3) == 1:
        m = m1 * m2 * m3 * m4 * m5
        M1 = m // m1
        M2 = m // m2
        M3 = m // m3
        M4 = m // m4
        M5 = m // m5
        M1p, _, _ = ext_gcd(M1, m1)
        M2p, _, _ = ext_gcd(M2, m2)
        M3p, _, _ = ext_gcd(M3, m3)
        M4p, _, _ = ext_gcd(M4, m4)
        M5p, _, _ = ext_gcd(M5, m5)
        x1 = M1 * M1p * a1
        x2 = M2 * M2p * a2
        x3 = M3 * M3p * a3
        x4 = M4 * M4p * a4
        x5 = M5 * M5p * a5
        x = (x1 + x2 + x3 + x4 + x5) % m
        return x
    else:
        print("不能直接利用中国剩余定理")
        return None

m2 = shengyu5(c2[0], c2[1], c2[2], c2[3], c2[4], n2[0], n2[1], n2[2], n2[3], n2[4])
getcontext().prec = 1000
m2_decimal = Decimal(m2)
result = m2_decimal ** Decimal('0.2')
plaintext_low_e = libnum.n2s(int(result))
print(f"低指数攻击结果: {plaintext_low_e}")
m[1] = 't is a f'
mx[3] = mx[8] = mx[12] = mx[16] = mx[20] = 't is a f'

# Pollard p-1 分解
print("\n6. Pollard p-1 分解攻击...")
def pollards_p_1(N, B):
    if B < 2:
        raise ValueError("B must be greater than or equal to 2")
    M = powmod(2, factorial(B), N)
    for i in range(1, B + 1):
        M_prime = (M - 1) % N
        g = gcd(M_prime, N)
        if g == N:
            break
        if g > 1 and g < N:
            return g
        M = powmod(M, i, N)
    return None

p3 = pollards_p_1(Nint[2], 1000)
q3 = Nint[2] // p3
fy3 = (p3-1) * (q3-1)
d3 = gmpy2.invert(eint[2], fy3)
m3 = fast_m_e(cint[2], d3, Nint[2])
print(f"Frame2解密: {libnum.n2s(m3)}")
m[6] = ' That is'
mx[2] = ' That is'

print("\n7. 已知因子分解...")
p6 = 920724637201
q6 = Nint[6] // p6
fy6 = (p6-1) * (q6-1)
d6 = gmpy2.invert(eint[6], fy6)
m6 = fast_m_e(cint[6], d6, Nint[6])
print(f"Frame6解密: {libnum.n2s(m6)}")
m[7] = 'Logic '
mx[6] = 'Logic '

p19 = 1085663496559
q19 = Nint[19] // p19
fy19 = (p19-1) * (q19-1)
d19 = gmpy2.invert(eint[19], fy19)
m19 = fast_m_e(cint[19], d19, Nint[19])
print(f"Frame19解密: {libnum.n2s(m19)}")
m[5] = 'instein.'
mx[19] = 'instein.'

# Fermat分解
def fermat_factorization(N):
    """Fermat分解法"""
    sqrt_N = gmpy2.isqrt(N)
    for x in range(sqrt_N, int(sqrt_N * 1.05) + 1):
        D = x**2 - N
        if D < 0:
            continue
        sqrt_D = gmpy2.isqrt(D)
        if sqrt_D ** 2 == D:
            p = x - sqrt_D
            q = x + sqrt_D
            if p * q == N:
                return p, q
    return None, None

print("\n8. 最终解密结果汇总:")
print("=" * 40)
print("解密出的明文片段:")
for i in range(len(m)):
    if m[i] != 0:
        print(f"位置 {i}: '{m[i]}'")

print(f"\n完整m数组: {m}")
print("\n解密进度: 部分帧已成功解密，还有空缺需要继续分析")

print("\n" + "=" * 60)
print("分析完成！")
print("=" * 60)